//-----------------------------------------------------------------------------
// Salvador Mendoza (salmg.net), 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Code for reading and emulating 14a technology aka MSDSal by Salvador Mendoza
//-----------------------------------------------------------------------------
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "string.h"
#include "BigBuf.h"
#include "iso14443a.h"
#include "protocols.h"
#include "cmd.h"

#define STATE_READ 0
#define STATE_EMU 1
#define DYNAMIC_RESPONSE_BUFFER_SIZE 64
#define DYNAMIC_MODULATION_BUFFER_SIZE 1024

void ModInfo(void)
{
    DbpString("  HF - Reading Visa cards & Emulating a Visa MSD Transaction(ISO14443) - (Salvador Mendoza)");
}

/* This standalone implements two different modes: reading and emulating.
*
* The initial mode is reading with LED A as guide.
* In this mode, the Proxmark expects a Visa Card,
* and will act as card reader. Trying to find track 2.
*
* If the Proxmark found a track 2, it will change to emulation mode (LED C) automatically.
* During this mode the Proxmark will behave as card, emulating a Visa MSD transaction
* using the pre-saved track2 from the previous reading.
*
* It is possible to jump from mode to another by simply pressing the button.
* However, to jump from reading to emulation mode, the LED C as to be on, which
* means having a track 2 in memory.
*
* Keep pressing the button down will quit the standalone cycle.
*
* LEDs:
* LED A = in reading mode
* LED C = in emulation(a track 2 in memory) mode
* LED A + LED C = in reading mode, but you can jump back to emulation mode by pressing the button
* LED B = receiving/sending commands, activity
*
*
* Reading or emulating ISO-14443A technology is not limited to payment cards. This example
* was not only designed to make a replay attack, but to open new possibilities in the ISO-14443A
* technologies. Be brave enough to share your knowledge & inspire others. Salvador Mendoza.
*/

static int Reply2Reader(tag_response_info_t *dynamic_response_info, uint8_t apdu_start, uint8_t *received_cmd, size_t cmd_len)
{
    uint8_t reply01[] = {0x6f, 0x15, 0x84, 0x0e, 0x31, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x03, 0x08, 0x01, 0x01, 0x90, 0x00};
    uint8_t reply02[] = {0x6f, 0x37, 0x84, 0x0e, 0x4e, 0x43, 0x2e, 0x65, 0x43, 0x61, 0x72, 0x64, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x25, 0x9f, 0x08, 0x01, 0x02, 0x9f, 0x0c, 0x1e, 0x6e, 0x65, 0x77, 0x63, 0x61, 0x70, 0x65, 0x63, 0x00, 0x05, 0xaa, 0x00, 0x00, 0x01, 0x88, 0x0a, 0x10, 0x00, 0x1a, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x6a, 0x90, 0x00};
    uint8_t reply03[] = {0x6e, 0x65, 0x77, 0x63, 0x61, 0x70, 0x65, 0x63, 0x00, 0x05, 0xaa, 0x00, 0x00, 0x01, 0x88, 0x0a, 0x10, 0x00, 0x1a, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x6f, 0x90, 0x00};

    uint8_t cmd01[] = {
        0x00,      // CLA
        0xA4,      // INS: Select
        0x00,      // P1:  Select MF, DF or EF
        0x00,      // P2
        0x02,      // Lc
        0x3f, 0x00 // DATA: MF
    };

    uint8_t cmd02[] = {
        0x00,                                                                              // CLA
        0xA4,                                                                              // INS: Select
        0x04,                                                                              // P1:  Select by DF name
        0x00,                                                                              // P2
        0x0e,                                                                              // Lc
        0x4e, 0x43, 0x2e, 0x65, 0x43, 0x61, 0x72, 0x64, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31 // DATA: NC.eCard.DDF01
    };

    uint8_t cmd03[] = {
        0x00, // CLA
        0xB0, // INS: Read Binary
        0x95, // P1
        0x00, // P2
        0x1e  // Le
    };

    uint8_t *p_apdu_cmd[3] = {cmd01, cmd02, cmd03};
    size_t apdu_cmd_len[3] = {sizeof(cmd01), sizeof(cmd02), sizeof(cmd03)};
    uint8_t *p_apdu_response[3] = {reply01, reply02, reply03};
    size_t apdu_response_len[3] = {sizeof(reply01), sizeof(reply02), sizeof(reply03)};

    for (int i = 0; i < 3; i++)
    {
        if (cmd_len < apdu_cmd_len[i])
        {
            continue;
        }
        else
        {
            if (0 != memcmp(&received_cmd[apdu_start], p_apdu_cmd[i], apdu_cmd_len[i]))
            {
                continue;
            }
            memcpy(dynamic_response_info->response, received_cmd, apdu_start);
            memcpy(&(dynamic_response_info->response[apdu_start]), p_apdu_response[i], apdu_response_len[i]);
            dynamic_response_info->response_n = apdu_start + apdu_response_len[i];
            return 0;
        }
    }
    dynamic_response_info->response_n = 0;
    return -1;
}

static int Emulation(uint8_t *uid)
{
    // UID 4 bytes(could be 7 bytes if needed it)
    uint8_t flags = FLAG_4B_UID_IN_DATA;
    // in case there is a read command received we shouldn't break
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    memcpy(data, uid, 4);

    // to initialize the emulation
    uint8_t tagType = 4; // 4 = ISO/IEC 14443-4 - javacard (JCOP)
    tag_response_info_t *responses;
    uint32_t cuid = 0;
    uint32_t counters[3] = {0x00, 0x00, 0x00};
    uint8_t tearings[3] = {0xbd, 0xbd, 0xbd};
    uint8_t pages = 0;

    // command buffers
    uint8_t receivedCmd[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedCmdPar[MAX_PARITY_SIZE] = {0x00};

    uint8_t dynamic_response_buffer[DYNAMIC_RESPONSE_BUFFER_SIZE] = {0};
    uint8_t dynamic_modulation_buffer[DYNAMIC_MODULATION_BUFFER_SIZE] = {0};

    tag_response_info_t *p_response = NULL;
    // handler - command responses
    tag_response_info_t dynamic_response_info = {
        .response = dynamic_response_buffer,
        .response_n = 0,
        .modulation = dynamic_modulation_buffer,
        .modulation_n = 0};

    SpinDelay(500);

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();
    if (false == SimulateIso14443aInit(tagType, flags, data, &responses, &cuid, counters, tearings, &pages))
    {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EINIT, NULL, 0);
        DbpString(_YELLOW_("!!") "Error initializing the emulation process!");
        return PM3_EFATAL;
    }
    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    for (;;)
    {
        LED_C_ON();
        // dynamic_response_info will be in charge of responses
        dynamic_response_info.response_n = 0;
        // command length
        int len = 0;

        // clean receive command buffer
        if (!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len))
        {
            DbpString(_YELLOW_("!!") "Emulator stopped");
            LED_C_OFF();
            return PM3_EOPABORTED;
        }

        // received a REQUEST
        if (receivedCmd[0] == ISO14443A_CMD_REQA && len == 1)
        {
            DbpString(_YELLOW_("+") "Received a REQA");
            p_response = &responses[RESP_INDEX_ATQA];
        }
        // received a HALT
        else if (receivedCmd[0] == ISO14443A_CMD_HALT && len == 4)
        {
            DbpString(_YELLOW_("+") "Received a HALT");
            p_response = NULL;
        }
        // received a WAKEUP
        else if (receivedCmd[0] == ISO14443A_CMD_WUPA && len == 1)
        {
            DbpString(_YELLOW_("+") "WAKEUP Received");
            p_response = &responses[RESP_INDEX_ATQA];
        }
        // received request for UID (cascade 1)
        else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 2)
        {
            DbpString(_YELLOW_("+") "Request for UID C1");
            p_response = &responses[RESP_INDEX_UIDC1];
        }
        // received a SELECT (cascade 1)
        else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 9)
        {
            DbpString(_YELLOW_("+") "Request for SELECT S1");
            p_response = &responses[RESP_INDEX_SAKC1];
        }
        // received a RATS request
        else if (receivedCmd[0] == ISO14443A_CMD_RATS && len == 4)
        {
            DbpString(_YELLOW_("+") "Request for RATS");
            p_response = &responses[RESP_INDEX_RATS];
        }
        else
        {
            DbpString(_YELLOW_("[ ") "Card reader command" _YELLOW_(" ]"));
            Dbhexdump(len, receivedCmd, false);

            // Check for ISO 14443A-4 compliant commands, look at left nibble
            switch (receivedCmd[0])
            {
            case 0x02:
            case 0x03:
            { // IBlock (command no CID)
                Reply2Reader(&dynamic_response_info, 1, receivedCmd, len);
            }
            break;
            case 0x0B:
            case 0x0A:
            { // IBlock (command CID)
                Reply2Reader(&dynamic_response_info, 2, receivedCmd, len);
            }
            break;

            case 0x1A:
            case 0x1B:
            { // Chaining command
                dynamic_response_info.response_n = 0;
            }
            break;

            case 0xAA:
            case 0xBB:
            {
                dynamic_response_info.response[0] = receivedCmd[0] ^ 0x11;
                dynamic_response_info.response_n = 2;
            }
            break;

            case 0xBA:
            { // ping / pong
                dynamic_response_info.response[0] = 0xAB;
                dynamic_response_info.response[1] = 0x01;
                dynamic_response_info.response_n = 2;
            }
            break;

            case 0xCA:
            case 0xC2:
            { // Readers sends deselect command
                dynamic_response_info.response[0] = 0xCA;
                dynamic_response_info.response[1] = 0x01;
                dynamic_response_info.response_n = 2;
            }
            break;

            default:
            {
                // Never seen this command before
                Dbprintf("Received unknown command (len=%d):", len);
                Dbhexdump(len, receivedCmd, false);
                // Do not respond
                dynamic_response_info.response_n = 0;
            }
            break;
            }
        }
        if (dynamic_response_info.response_n > 0)
        {
            DbpString(_GREEN_("[ ") "Proxmark3 answer" _GREEN_(" ]"));
            Dbhexdump(dynamic_response_info.response_n, dynamic_response_info.response, false);
            DbpString("----");

            // add CRC bytes, always used in ISO 14443A-4 compliant cards
            AddCrc14A(dynamic_response_info.response, dynamic_response_info.response_n);
            dynamic_response_info.response_n += 2;

            if (prepare_tag_modulation(&dynamic_response_info, DYNAMIC_MODULATION_BUFFER_SIZE) == false)
            {
                SpinDelay(500);
                DbpString(_YELLOW_("!!") "Error preparing Proxmark to answer!");
                continue;
            }
            p_response = &dynamic_response_info;
        }
        if (p_response != NULL)
        {
            EmSendPrecompiledCmd(p_response);
            LED_C_OFF();
            p_response = NULL;
        }
    }
    return PM3_SUCCESS;
}

static int Reading(uint8_t *uid)
{
    //For reading process
    iso14a_card_select_t card_a_info;
    iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
    if (iso14443a_select_card(uid, &card_a_info, NULL, true, 1, false)) {
        Dbprintf("UID:");
        Dbhexdump(card_a_info.uidlen, card_a_info.uid, false);
        return PM3_SUCCESS;
    }
    return PM3_EFATAL;
}

void RunMod(void)
{
    StandAloneMode();
    DbpString(_YELLOW_(">>") "Reading badegt cards & Emulating a Visa MSD Transaction a.k.a. MSDSal Started " _YELLOW_("<<"));
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    static uint8_t uid[10] = {0xbf, 0x88, 0x69, 0x3e};
    // to check emulation status
    int retval = PM3_SUCCESS;
    
    clear_trace();
    set_tracing(true);

    for (;;)
    {
        WDT_HIT();
    
        // exit from RunMod, send a usbcommand.
        if (data_available())
            break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);
        if (button_pressed == BUTTON_HOLD){
            SpinErr(LED_A, 300, 3);
            DbpString(_YELLOW_("[=]") "BUTTON_HOLD!");
            break;
        }
        else if (button_pressed == BUTTON_SINGLE_CLICK)
        {
            // pressing one time change between reading & emulation
            DbpString(_YELLOW_("[ ") "In reading mode" _YELLOW_(" ]"));
            int ret = Reading(uid);
            if(PM3_SUCCESS != ret && uid[0] < 255){
                DbpString(_YELLOW_("!!") "No card selected! uid+1");
                uid[0]++;
                Dbprintf("Current UID:");
                Dbhexdump(4, uid, false);
                SpinErr(LED_B,200,2);
            }else{
                DbpString(_YELLOW_("+") "Found ISO 14443 Type A!");
                SpinUp(100);
            }
        }

        DbpString(_YELLOW_("[ ") "In emulation mode" _YELLOW_(" ]"));
        retval = Emulation(uid);
    }

    switch_off();

    BigBuf_free_keep_EM();
    reply_ng(CMD_HF_MIFARE_SIMULATE, retval, NULL, 0);

    DbpString(_YELLOW_("[=]") "exiting");
    LEDsoff();
}
