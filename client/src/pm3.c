//-----------------------------------------------------------------------------
// User API
//-----------------------------------------------------------------------------

#include "pm3.h"

#include <stdlib.h>

#include "proxmark3.h"
#include "cmdmain.h"
#include "ui.h"
#include "usart_defs.h"
#include "util_posix.h"
#include "comms.h"

pm3_device_t *pm3_open(char *port) {
    pm3_init();
    OpenProxmark(&g_session.current_device, port, false, 20, false, USART_BAUD_RATE);
    if (g_session.pm3_present && (TestProxmark(g_session.current_device) != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " cannot communicate with the Proxmark\n");
        CloseProxmark(g_session.current_device);
    }

    if ((port != NULL) && (!g_session.pm3_present))
        exit(EXIT_FAILURE);

    if (!g_session.pm3_present)
        PrintAndLogEx(INFO, "Running in " _YELLOW_("OFFLINE") " mode");
    // For now, there is no real device context:
    return g_session.current_device;
}

void pm3_close(pm3_device_t *dev) {
    // Clean up the port
    if (g_session.pm3_present) {
        clearCommandBuffer();
        SendCommandNG(CMD_QUIT_SESSION, NULL, 0);
        msleep(100); // Make sure command is sent before killing client
        CloseProxmark(dev);
    }
}

int pm3_console(pm3_device_t *dev, char *Cmd) {
    // For now, there is no real device context:
    (void) dev;
    return CommandReceived(Cmd);
}

const char *pm3_name_get(pm3_device_t *dev) {
    return dev->g_conn->serial_port_name;
}

pm3_device_t *pm3_get_current_dev(void) {
    return g_session.current_device;
}
