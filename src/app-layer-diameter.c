/* Copyright (C) 2015-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Ma Duc <mavietduc@gmail.com>
 *
 * Diameter application layer detector and parser for learning and
 * diameter purposes.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "stream.h"
#include "conf.h"
#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-diameter.h"

#include "util-unittest.h"
#include "util-validate.h"
#include "util-enum.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define DIAMETER_DEFAULT_PORT "3868"

/* The minimum size for a message. For some protocols this might
 * be the size of a header. */
#define DIAMETER_MIN_FRAME_LEN 20

/**
 * Tổng hợp các event của lớp application cho protocol.
 * Thông thường, có thể xảy ra các event lỗi khi phân tích cú pháp
 * dữ liệu, như dữ liệu được nhận không mong muốn. Với Diameter,
 * chúng ta sẽ tạo ra một thứ nào đó và log lại alert lớp app-layer
 * nếu nhận được một bản tin trống
 * 
 * Ví dụ rule:
 * alert diameter any any -> any any (msg:"SURICATA Diameter empty message"; \
 *    app-layer-event:diameter.empty_message; sid:X; rev:Y;)
*/
enum {
    DIAMETER_DECODER_EVENT_EMPTY_MESSAGE,
    DIAMETER_DECODER_EVENT_ERROR_MESSAGE,
    DIAMETER_SENDING_MESSAGE,
    DIAMETER_RECIVE_SUCCESS_MESSAGE
};

SCEnumCharMap diameter_decoder_event_table[] = {
    {"EMPTY_MESSAGE", DIAMETER_DECODER_EVENT_EMPTY_MESSAGE},
    {"ERROR_MESSAGE", DIAMETER_DECODER_EVENT_ERROR_MESSAGE},
    {"DIAMETER_SENDING",DIAMETER_SENDING_MESSAGE},
    {"DIAMETER_SUCESS",DIAMETER_RECIVE_SUCCESS_MESSAGE},

    // event table must be NULL-terminated
    { NULL, -1 },
};

// static uint8_t toBinaryAt(uint8_t a, uint8_t point) {
//     uint8_t i,j=0;
//     uint8_t result[8];
//     for(i=0x80;i!=0;i>>=1) {
//         result[j] = ((a&i)? 1:0); j++;
//     }
//     return result[point];
// }

static uint32_t BytesToInt32(uint8_t* bytes) {
    return (uint32_t) (bytes[0] + (bytes[1] << 8) + (bytes[2] << 16) + (bytes[3] << 24));
}

static DiameterTransaction *DiameterTxAlloc(DiameterState *state)
{
    DiameterTransaction *tx = SCCalloc(1, sizeof(DiameterTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    // Increment the transaction ID on the state each time one is llocated.
    state->transaction_max++;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}


static void DiameterTxFree(void *txv)
{
    DiameterTransaction *tx = (DiameterTransaction *)txv;

    AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    if (tx->request.start_pointer != NULL) 
        SCFree(tx->request.start_pointer);

    if (tx->response.start_pointer != NULL) 
        SCFree(tx->response.start_pointer);

    AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    SCFree(tx);
}

static void *DiameterStateAlloc(void *orig_state, AppProto proto_orig)
{
    SCLogNotice("Allocating diameter state.");
    DiameterState *state = SCCalloc(1, sizeof(DiameterState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void DiameterStateFree(void *state)
{
    DiameterState *diameter_state = state;
    DiameterTransaction *tx;
    SCLogNotice("Freeing diameter state.");

    while ((tx = TAILQ_FIRST(&diameter_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&diameter_state->tx_list, tx, next);
        DiameterTxFree(tx);
    } 
    SCFree(diameter_state);
}

static int DiameterStateGetEventInfo(const char *event_name, int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, diameter_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "diameter enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int DiameterStateGetEventInfoById(int event_id, const char **event_name, AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, diameter_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "diameter enum map table.",  event_id);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

/**
 * \brief Khảo sát xem data đến có là Diameter không.
 *
 * \retval ALPROTO_DIAMETER nếu giống như Diameter,
 *     ALPROTO_FAILED, nếu rõ ràng không phải ALPROTO_DIAMETER,
 *     nếu không thì ALPROTO_UNKNOWN.
 */
static AppProto DiameterProbingParser(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Kiểm tra Diameter ở đây. */
    if (input_len <= DIAMETER_MIN_FRAME_LEN) {
        SCLogInfo("Detected as ALPROTO_UNKNOWN!");
        return ALPROTO_UNKNOWN;
    }

    // Xac dinh dua vao version cua diameter va 4 bit cuoi cua byte thu 5 (byte flags)
    // Version duy nhat duoc ho tro hien nay la: 0x01
    // 4 bit cuoi cua byte flags luon bang: 0
    if (input[0] == 0x01 /*&& ((input[4] << 4) == 0x0)*/ ) {
        SCLogNotice("Detected as ALPROTO_DIAMETER");
        return ALPROTO_DIAMETER;
    }

    SCLogInfo("Protocol not detected as ALPROTO_DIAMETER.");
    return ALPROTO_FAILED;
}

/* Decode bản tin đọc header ở đây */
static AppLayerResult DiameterDecode(Flow *f, uint8_t direction, void *alstate,
        AppLayerParserState *pstate, StreamSlice stream_slice)
{
    DiameterState *state = (DiameterState *)alstate;
    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);
    // const uint8_t flags = StreamSliceGetFlags(&stream_slice);

    if (input == NULL &&
        ((direction == 0 && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) ||
                (direction == 1 &&
                        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)))) {
        goto end;
    } else if (input == NULL || input_len == 0) {
        return APP_LAYER_ERROR;
    }

    

    /* Check có đúng là Diameter không */
    DiameterPacket* packet = NULL;
    DiameterPacketInit(packet);

    packet = ParseDiameterPacket(input, input_len);
    if (BytesToInt32(packet->start_pointer + packet->length.offset) != input_len) {
        SCLogNotice("Bản tin Diameter nhận diện không đúng");
        return APP_LAYER_ERROR;
    }
    // SCLogNotice("Parsing diameter message: len=%"PRIu32". CommandCode=%"PRIu32, input_len, diameter_header.CommandCode);
    // SCLogNotice("Transaction max=%"PRIu64, state->transaction_max);

    /* Tạo Tx cho bản tin này */

    if (direction == 0) {
        DiameterTransaction *tx = DiameterTxAlloc(state);
        if (unlikely(tx == NULL)) {
            SCLogNotice("Failed to allocate new Diameter tx.");
            goto end;
        }
        tx->request = *packet;
    } else if (direction == 1 ) {
        DiameterTransaction *tx = NULL, *ttx;
        TAILQ_FOREACH(ttx, &state->tx_list, next) 
            tx = ttx;
        if ( tx->request.start_pointer != NULL) {
            tx->response = *packet;
        }
        goto end;
    } else {
        SCReturn(APP_LAYER_ERROR);
    }
    /*
    if (unlikely(tx->data == NULL)) {
        goto end;
    }*/

end:
    SCReturn(APP_LAYER_OK);
}

static AppLayerResult DiameterParseRequest(Flow *f, void *alstate, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return DiameterDecode(f, 0 /* toserver */, alstate, pstate, stream_slice);
}


static AppLayerResult DiameterParseResponse(Flow *f, void *alstate, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return DiameterDecode(f, 1 /* toclient */, alstate, pstate, stream_slice);
}

// free transaction ung voi hop by hop id 
static void DiameterStateTxFree(void *state, uint64_t tx_id)
{
    DiameterState *tmp = state;
    DiameterTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &tmp->tx_list, next, ttx) {

        if (tx->tx_id != tx_id)
            continue;

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&tmp->tx_list, tx, next);
        DiameterTxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static uint64_t DiameterGetTxCnt(void *statev)
{
    return 1;
}

static int DiameterGetStateProgress(void *txv, uint8_t direction)
{
    if (direction & STREAM_TOCLIENT) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        return 1;
    }

    return 0;
}

static void *DiameterGetTx(void *state, uint64_t tx_id)
{
    DiameterState *diameter_state = (DiameterState *)state;
    return diameter_state;
}

/**
 * \brief retrieve the tx data used for logging, config, detection
 */
static AppLayerTxData *DiameterGetTxData(void *vtx)
{
    DiameterTransaction *tx = (DiameterTransaction *)vtx;
    return &tx->tx_data;
}

/**
 * \brief retrieve the state data
 */
static AppLayerStateData *DiameterGetStateData(void *vstate)
{
    DiameterState *state = (DiameterState *)vstate;
    return &state->state_data;
}

void DiameterPacketInit(DiameterPacket *packet) {
    DiameterPacket* tmp = packet;
    tmp = SCCalloc(1,sizeof(DiameterPacket));
    tmp->start_pointer = NULL;
}
/**
 * Parse diameter packet
 * Để đơn giản hiện tại chỉ parse header và coi như gói tin không bị phân mảnh
*/
DiameterPacket *ParseDiameterPacket(const uint8_t *input, uint32_t input_len) {
    DiameterPacket* packet;
    DiameterPacketInit(packet);

    if (input_len < DIAMETER_MIN_FRAME_LEN) {
        return packet;
    }
    packet->start_pointer = SCCalloc(1,input_len);

    memcpy(packet->start_pointer, input, input_len);

    packet->hdr_len = 20;;
    packet->version =  (data){0,1};
    packet->length = (data){1,3};
    packet->flags = (data){4,1};
    packet->commandCode = (data){5,3};
    packet->applicationId = (data){8,4};
    packet->hopbyHopId = (data){12,4};
    packet->endtoEndId = (data){16,4};
    return packet;
}

void RegisterDiameterParsers(void)
{
    const char *proto_name = "diameter";

    /* Check if Diameter TCP detection is enabled. If it does not exist in
     * the configuration file then it will be disabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_DIAMETER, proto_name);
        SCLogDebug("Diameter TCP protocol detection enabled.");

        if (RunmodeIsUnittests()) {
            SCLogNotice("Unittest mode, registering default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, DIAMETER_DEFAULT_PORT, ALPROTO_DIAMETER, 0, DIAMETER_MIN_FRAME_LEN, STREAM_TOSERVER, DiameterProbingParser, NULL);
        }
        else {
            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_DIAMETER, 0, DIAMETER_MIN_FRAME_LEN, DiameterProbingParser, NULL)) {
                SCLogDebug("No diameter app-layer configuration, enabling echo detection TCP detection on port %s.", DIAMETER_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP, DIAMETER_DEFAULT_PORT, ALPROTO_DIAMETER, 0, DIAMETER_MIN_FRAME_LEN, STREAM_TOSERVER, DiameterProbingParser, NULL);
            }
        }
    }

    else {
        SCLogDebug("Protocol detector and parser disabled for Diameter.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogNotice("Registering Diameter protocol parser.");

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterStateAlloc, DiameterStateFree);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DIAMETER, STREAM_TOSERVER, DiameterParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DIAMETER, STREAM_TOCLIENT, DiameterParseResponse);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterStateTxFree);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetTxCnt);

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_DIAMETER, STREAM_TOSERVER);
        // AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOSERVER);

        /* Transaction handling. */
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_DIAMETER, 1, 1);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetStateData);
        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterStateGetEventInfoById);

        /* Leave this is if your parser can handle gaps, otherwise remove. */
        // AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_DIAMETER, APP_LAYER_PARSER_OPT_ACCEPT_GAPS);
    }
    else {
        SCLogDebug("Diameter protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_DIAMETER,
        DiameterParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void DiameterParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}