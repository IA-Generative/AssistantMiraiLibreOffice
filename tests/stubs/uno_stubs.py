"""
Inject fake UNO modules so that src.mirai.entrypoint can be imported
and tested outside of LibreOffice.

Usage — call install() before importing anything from src.mirai.entrypoint:

    from tests.stubs.uno_stubs import install
    install()
    from src.mirai.entrypoint import MainJob
"""
import sys
from unittest.mock import MagicMock


# Each UNO interface used as a base class must be a *distinct* Python class;
# reusing `object` for all of them causes "duplicate base class" errors.
class _UnoBase:          pass
class _XJobExecutor:     pass
class _XJob:             pass
class _XActionListener:  pass
class _XItemListener:    pass
class _XMouseListener:   pass
class _XWindowListener:  pass
class _XTopWindowListener: pass
class _XNamed:           pass
class _XSelectionChangeListener: pass


def install():
    """Patch sys.modules with UNO stubs. Idempotent."""
    if sys.modules.get("uno") and getattr(sys.modules["uno"], "_STUB", False):
        return

    # --- uno ---
    uno = MagicMock()
    uno._STUB = True
    uno.fileUrlToSystemPath = lambda url: url.replace("file://", "")
    uno.systemPathToFileUrl = lambda path: "file://" + path
    uno.createUnoStruct = MagicMock(return_value=MagicMock())

    # --- unohelper ---
    unohelper = MagicMock()
    unohelper.Base = _UnoBase          # real class, not object

    # --- officehelper ---
    officehelper = MagicMock()

    # --- com.sun.star.task ---
    com_sun_star_task = MagicMock()
    com_sun_star_task.XJobExecutor = _XJobExecutor
    com_sun_star_task.XJob = _XJob

    # --- com.sun.star.awt ---
    com_sun_star_awt = MagicMock()
    com_sun_star_awt.MessageBoxButtons = MagicMock()
    com_sun_star_awt.MessageBoxType = MagicMock()
    com_sun_star_awt.XActionListener  = _XActionListener
    com_sun_star_awt.XItemListener    = _XItemListener
    com_sun_star_awt.XMouseListener   = _XMouseListener
    com_sun_star_awt.XWindowListener  = _XWindowListener
    com_sun_star_awt.XTopWindowListener = _XTopWindowListener

    com_sun_star_awt_msgtype = MagicMock()
    com_sun_star_awt_msgtype.MESSAGEBOX = 0

    # --- com.sun.star.beans / container ---
    com_sun_star_beans = MagicMock()
    com_sun_star_beans.PropertyValue = MagicMock

    com_sun_star_container = MagicMock()
    com_sun_star_container.XNamed = _XNamed

    # --- com.sun.star.view ---
    com_sun_star_view = MagicMock()
    com_sun_star_view.XSelectionChangeListener = _XSelectionChangeListener

    # --- register all modules ---
    sys.modules.update({
        "uno": uno,
        "unohelper": unohelper,
        "officehelper": officehelper,
        "com": MagicMock(),
        "com.sun": MagicMock(),
        "com.sun.star": MagicMock(),
        "com.sun.star.task": com_sun_star_task,
        "com.sun.star.awt": com_sun_star_awt,
        "com.sun.star.awt.MessageBoxType": com_sun_star_awt_msgtype,
        "com.sun.star.beans": com_sun_star_beans,
        "com.sun.star.container": com_sun_star_container,
        "com.sun.star.view": com_sun_star_view,
        "com.sun.star.frame": MagicMock(),
        "com.sun.star.lang": MagicMock(),
        "com.sun.star.deployment": MagicMock(),
    })


def make_job(config_dir=None):
    """
    Instantiate MainJob with a fully mocked UNO context.

    Args:
        config_dir: directory used as UserConfig (defaults to /tmp).
                    Pass a real tempfile.mkdtemp() path for tests that write files.
    Returns:
        A MainJob instance ready for unit testing.
    """
    install()

    from src.mirai.entrypoint import MainJob

    path_settings = MagicMock()
    path_settings.UserConfig = config_dir or "/tmp/test_libreoffice_config"

    service_manager = MagicMock()
    service_manager.createInstanceWithContext.return_value = path_settings

    ctx = MagicMock()
    ctx.ServiceManager = service_manager
    ctx.getServiceManager.return_value = service_manager

    return MainJob(ctx)
