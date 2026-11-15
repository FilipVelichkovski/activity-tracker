// KWin 6 Wayland bridge script for Activity Tracker.
// Reports ONLY the currently active window, along with whether it is visible
// (not minimized and not hidden by "Show Desktop").

const DBUS_SERVICE = "org.antigravity.ActivityTracker";
const DBUS_PATH = "/Tracker";
const DBUS_IFACE = "org.antigravity.ActivityTracker";
const DBUS_METHOD = "UpdateWindow";

let trackedWin = null;
let minimizedHandler = null;
let captionHandler = null;

function emitWindowState(win) {
    let isVisibleActive = false;
    let app = "";
    let title = "";
    let pid = 0;

    if (win && !win.minimized && !workspace.showingDesktop) {
        isVisibleActive = true;
        app = String(win.resourceClass || win.resourceName || "unknown");
        title = String(win.caption || "");
        pid = Number(win.pid || 0);
    }

    callDBus(DBUS_SERVICE, DBUS_PATH, DBUS_IFACE, DBUS_METHOD,
             app, title, pid, isVisibleActive);
}

function detachTrackedWindow() {
    if (trackedWin) {
        try {
            if (minimizedHandler) {
                trackedWin.minimizedChanged.disconnect(minimizedHandler);
            }
            if (captionHandler) {
                trackedWin.captionChanged.disconnect(captionHandler);
            }
        } catch (e) {
            // Window may already be destroyed
        }
    }
    trackedWin = null;
    minimizedHandler = null;
    captionHandler = null;
}

function attachWindow(win) {
    detachTrackedWindow();
    if (win) {
        trackedWin = win;
        minimizedHandler = function() {
            emitWindowState(trackedWin);
        };
        captionHandler = function() {
            emitWindowState(trackedWin);
        };
        try {
            trackedWin.minimizedChanged.connect(minimizedHandler);
            trackedWin.captionChanged.connect(captionHandler);
        } catch (e) {
            // Ignore if signals cannot be connected
        }
    }
    emitWindowState(win);
}

workspace.windowActivated.connect(function(win) {
    attachWindow(win);
});

if (workspace.showingDesktopChanged) {
    workspace.showingDesktopChanged.connect(function() {
        emitWindowState(workspace.activeWindow);
    });
}

// Emit initial state on script load
attachWindow(workspace.activeWindow);
