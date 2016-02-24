import os
import traceback


def is_user_admin():
    """
    Determines if current user is root/administrator.
    Works for nt (Windows >= XP SP2) and posix (unix, I.E: Linux, OSX, etc..).

    :rtype: bool
    """
    if os.name == 'nt':
        import ctypes
        # WARNING: requires Windows XP SP2 or higher!
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            traceback.print_exc()
            print("Admin check failed, assuming not an admin.")
            return False
    elif os.name == 'posix':
        # Check for root on Posix
        return os.getuid() == 0
    else:
        raise RuntimeError("Unsupported operating system for this module: %s" % (os.name,))
