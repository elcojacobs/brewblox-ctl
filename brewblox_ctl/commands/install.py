"""
Brewblox-ctl installation commands
"""

from time import sleep
from typing import Optional, Tuple

import click

from brewblox_ctl import actions, click_helpers, const, utils
from brewblox_ctl.commands import snapshot
from brewblox_ctl.utils import sh


@click.group(cls=click_helpers.OrderedGroup)
def cli():
    """Command collector"""


class InstallOptions:
    def __init__(self) -> None:
        self.use_defaults: bool = False
        self.skip_confirm: bool = True

        self.apt_install: bool = True

        self.docker_install: bool = True
        self.docker_group_add: bool = True
        self.docker_pull: bool = True

        self.reboot_needed: bool = False
        self.prompt_reboot: bool = True

        self.init_compose: bool = True
        self.init_auth: bool = True
        self.init_datastore: bool = True
        self.init_history: bool = True
        self.init_gateway: bool = True
        self.init_eventbus: bool = True

        self.enable_auth: bool = True
        self.user_info: Optional[Tuple[str, str]] = None

    def check_confirm_opts(self):
        self.use_defaults = False
        self.skip_confirm = True

        self.use_defaults = utils.confirm('Do you want to install with default settings?')

        if not self.use_defaults:
            self.skip_confirm = utils.confirm(
                'Do you want to disable the confirmation prompt for brewblox-ctl commands?')

    def check_system_opts(self):
        self.apt_install = True

        apt_deps = ' '.join(const.APT_DEPENDENCIES)
        if not utils.command_exists('apt-get'):
            utils.info('`apt-get` is not available. You may need to find another way to install dependencies.')
            utils.info(f'Apt packages: "{apt_deps}"')
            self.apt_install = False
        elif not self.use_defaults:
            self.apt_install = utils.confirm('Do you want brewblox-ctl to install and update system (apt) packages? ' +
                                             f'Installed packages: `{apt_deps}`.')

    def check_docker_opts(self):
        self.docker_install = True
        self.docker_group_add = True
        self.docker_pull = True

        if utils.command_exists('docker'):
            utils.info('Docker is already installed.')
            self.docker_install = False
        elif not self.use_defaults:
            self.docker_install = utils.confirm('Do you want to install docker?')

        if utils.is_docker_user():
            user = utils.getenv('USER')
            utils.info(f'{user} already belongs to the docker group.')
            self.docker_group_add = False
        elif not self.use_defaults:
            self.docker_group_add = utils.confirm('Do you want to run docker commands without sudo?')

        if not self.use_defaults:
            self.docker_pull = utils.confirm('Do you want to pull the docker images for your services?')

    def check_reboot_opts(self):
        self.reboot_needed = False
        self.prompt_reboot = True

        if self.docker_install \
            or self.docker_group_add \
                or utils.is_docker_user() and not utils.has_docker_rights():
            self.reboot_needed = True
            self.prompt_reboot = utils.confirm('A reboot is required after installation. ' +
                                               'Do you want to be prompted before that happens?')

    def check_init_opts(self):
        self.init_compose = True
        self.init_auth = True
        self.init_datastore = True
        self.init_history = True
        self.init_gateway = True
        self.init_eventbus = True
        self.init_spark_backup = True

        self.enable_auth = True
        self.user_info = None

        if utils.path_exists('./docker-compose.yml'):
            self.init_compose = not utils.confirm('This directory already contains a docker-compose.yml file. ' +
                                                  'Do you want to keep it?')

        if utils.path_exists('./auth/'):
            self.init_auth = not utils.confirm('This directory already contains user authentication files. '
                                               'Do you want to keep them?')

        if utils.path_exists('./redis/'):
            self.init_datastore = not utils.confirm('This directory already contains Redis datastore files. ' +
                                                    'Do you want to keep them?')

        if utils.path_exists('./victoria/'):
            self.init_history = not utils.confirm('This directory already contains Victoria history files. ' +
                                                  'Do you want to keep them?')

        if utils.path_exists('./traefik/'):
            self.init_gateway = not utils.confirm('This directory already contains Traefik gateway files. ' +
                                                  'Do you want to keep them?')

        if utils.path_exists('./mosquitto/'):
            self.init_eventbus = not utils.confirm('This directory already contains Mosquitto config files. ' +
                                                   'Do you want to keep them?')

        if utils.path_exists('./spark/backup/'):
            self.init_spark_backup = not utils.confirm('This directory already contains Spark backup files. ' +
                                                       'Do you want to keep them?')

        self.enable_auth = utils.confirm('Do you want to enable password authentication for UI access?')

        if self.enable_auth and self.init_auth:
            utils.info('Please set username and password for UI access')
            self.user_info = utils.prompt_user_info()


@cli.command()
@click.pass_context
@click.option('--snapshot', 'snapshot_file',
              help='Load system snapshot generated by `brewblox-ctl snapshot save`.')
def install(ctx: click.Context, snapshot_file):
    """Install Brewblox and its dependencies.

    Brewblox can be installed multiple times on the same computer.
    Settings and databases are stored in a Brewblox directory.

    This command also installs system-wide dependencies.
    A reboot is required after installing docker, or adding the user to the 'docker' group.

    By default, `brewblox-ctl install` attempts to download packages using the apt package manager.
    If you are using a system without apt (eg. Synology NAS), this step will be skipped.
    You will need to manually install any missing libraries.

    When using the `--snapshot ARCHIVE` option, no dir is created.
    Instead, the directory in the snapshot is extracted.
    It will be renamed to the desired name of the Brewblox directory.

    \b
    Steps:
        - Ask confirmation for installation steps.
        - Install apt packages.
        - Install docker.
        - Add user to 'docker' group.
        - Fix host IPv6 settings.
        - Disable host-wide mDNS reflection.
        - Set variables in .env file.
        - If snapshot provided:
            - Load configuration from snapshot.
        - Else:
            - Check for port conflicts.
            - Create docker compose configuration files.
            - Create datastore (Redis) directory.
            - Create history (Victoria) directory.
            - Create gateway (Traefik) directory.
            - Create SSL certificates.
            - Create eventbus (Mosquitto) directory.
            - Set version number in .env file.
        - Pull docker images.
        - Reboot if needed.
    """
    utils.confirm_mode()
    user = utils.getenv('USER')
    opts = InstallOptions()

    opts.check_confirm_opts()
    opts.check_system_opts()
    opts.check_docker_opts()
    opts.check_reboot_opts()

    if not snapshot_file:
        opts.check_init_opts()

    # Install Apt packages
    if opts.apt_install:
        utils.info('Installing apt packages...')
        apt_deps = ' '.join(const.APT_DEPENDENCIES)
        sh([
            'sudo apt-get update',
            'sudo apt-get upgrade -y',
            f'sudo apt-get install -y {apt_deps}',
        ])
    else:
        utils.info('Skipped: apt-get install.')

    # Install docker
    if opts.docker_install:
        utils.info('Installing docker...')
        sh('curl -sL get.docker.com | sh', check=False)
    else:
        utils.info('Skipped: docker install.')

    # Add user to 'docker' group
    if opts.docker_group_add:
        utils.info(f"Adding {user} to 'docker' group...")
        sh('sudo usermod -aG docker $USER')
    else:
        utils.info(f"Skipped: adding {user} to 'docker' group.")

    # Always apply actions
    actions.check_compose_plugin()
    actions.disable_ssh_accept_env()
    actions.fix_ipv6(None, False)
    actions.edit_avahi_config()
    actions.add_particle_udev_rules()
    actions.uninstall_old_ctl_package()
    actions.deploy_ctl_wrapper()

    # Set variables in .env file
    # Set version number to 0.0.0 until snapshot load / init is done
    utils.info('Setting .env values...')
    utils.setenv(const.ENV_KEY_CFG_VERSION, '0.0.0')
    utils.setenv(const.ENV_KEY_SKIP_CONFIRM, str(opts.skip_confirm))
    utils.setenv(const.ENV_KEY_UPDATE_SYSTEM_PACKAGES, str(opts.apt_install))
    utils.setenv(const.ENV_KEY_AUTH_ENABLED, str(opts.enable_auth))
    utils.defaultenv()

    # Install process splits here
    # Either load all config files from snapshot or run init
    sudo = utils.optsudo()
    if snapshot_file:
        ctx.invoke(snapshot.load, file=snapshot_file)
    else:
        release = utils.getenv('BREWBLOX_RELEASE')

        utils.info('Checking for port conflicts...')
        actions.check_ports()

        utils.info('Copying docker-compose.shared.yml...')
        sh(f'cp -f {const.DIR_DEPLOYED_CONFIG}/docker-compose.shared.yml ./')

        if opts.init_compose:
            utils.info('Copying docker-compose.yml...')
            sh(f'cp -f {const.DIR_DEPLOYED_CONFIG}/docker-compose.yml ./')

        # Stop after we're sure we have a compose file
        utils.info('Stopping services...')
        sh(f'{sudo}docker compose down')

        if opts.init_datastore:
            utils.info('Creating datastore directory...')
            sh('sudo rm -rf ./redis/; mkdir ./redis/')

        if opts.init_auth:
            utils.info('Creating auth directory...')
            sh('sudo rm -rf ./auth/; mkdir ./auth/')

        if opts.init_history:
            utils.info('Creating history directory...')
            sh('sudo rm -rf ./victoria/; mkdir ./victoria/')

        if opts.init_gateway:
            utils.info('Creating gateway directory...')
            sh('sudo rm -rf ./traefik/; mkdir ./traefik/')

            utils.info('Creating SSL certificate...')
            actions.makecert('./traefik', release)

        if opts.init_eventbus:
            utils.info('Creating mosquitto config directory...')
            sh('sudo rm -rf ./mosquitto/; mkdir ./mosquitto/')

        if opts.init_spark_backup:
            utils.info('Creating Spark backup directory...')
            sh('sudo rm -rf ./spark/backup/; mkdir -p ./spark/backup/')

        if opts.user_info:
            utils.info('Creating user for UI authentication...')
            utils.add_user(*opts.user_info)

        # Always copy cert config to traefik dir
        sh(f'cp -f {const.DIR_DEPLOYED_CONFIG}/traefik-cert.yaml ./traefik/')

        # Init done - now set CFG version
        utils.setenv(const.ENV_KEY_CFG_VERSION, const.CFG_VERSION)

    if opts.docker_pull:
        utils.info('Pulling docker images...')
        sh(f'{sudo}docker compose pull')

    utils.info('All done!')

    # Reboot
    if opts.reboot_needed:
        if opts.prompt_reboot:
            utils.info('Press ENTER to reboot.')
            input()
        else:
            utils.info('Rebooting in 10 seconds...')
            sleep(10)
        sh('sudo reboot')


@cli.command()
@click.option('--dir',
              default='./traefik',
              help='Target directory for generated certs.')
@click.option('--release',
              default=None,
              help='Brewblox release track.')
def makecert(dir, release):
    """Generate a self-signed SSL certificate.

    \b
    Steps:
        - Create directory if it does not exist.
        - Create brewblox.crt and brewblox.key files.
    """
    utils.confirm_mode()
    actions.makecert(dir, release)
