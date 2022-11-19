/* Copyright (C) 2015-2021 Open Information Security Foundation
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

/*
 * TODO: Update \author in this file and in output-json-test1.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer Test1.
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-test1.h"
#include "output-json-test1.h"

typedef struct LogTest1FileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogTest1FileCtx;

typedef struct LogTest1LogThread_ {
    LogTest1FileCtx *test1log_ctx;
    OutputJsonThreadCtx *ctx;
} LogTest1LogThread;

static int JsonTest1Logger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    Test1Transaction *test1tx = tx;
    LogTest1LogThread *thread = thread_data;

    SCLogNotice("Logging test1 transaction %"PRIu64".", test1tx->tx_id);

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "test1", NULL, thread->test1log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "test1");

    /* Log the request buffer. */
    if (test1tx->request_buffer != NULL) {
        jb_set_string_from_bytes(js, "request", test1tx->request_buffer,
                test1tx->request_buffer_len);
    }

    /* Log the response buffer. */
    if (test1tx->response_buffer != NULL) {
        jb_set_string_from_bytes(js, "response", test1tx->response_buffer,
                test1tx->response_buffer_len);
    }

    /* Close test1. */
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);

    jb_free(js);
    return TM_ECODE_OK;
}

static void OutputTest1LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogTest1FileCtx *test1log_ctx = (LogTest1FileCtx *)output_ctx->data;
    SCFree(test1log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputTest1LogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogTest1FileCtx *test1log_ctx = SCCalloc(1, sizeof(*test1log_ctx));
    if (unlikely(test1log_ctx == NULL)) {
        return result;
    }
    test1log_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(test1log_ctx);
        return result;
    }
    output_ctx->data = test1log_ctx;
    output_ctx->DeInit = OutputTest1LogDeInitCtxSub;

    SCLogNotice("Test1 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TEST1);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonTest1LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogTest1LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogTest1.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->test1log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->test1log_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonTest1LogThreadDeinit(ThreadVars *t, void *data)
{
    LogTest1LogThread *thread = (LogTest1LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonTest1LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonTest1Log", "eve-log.test1",
            OutputTest1LogInitSub, ALPROTO_TEST1, JsonTest1Logger,
            JsonTest1LogThreadInit, JsonTest1LogThreadDeinit, NULL);

    SCLogNotice("Test1 JSON logger registered.");
}
