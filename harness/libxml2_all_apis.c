/*
 * Multi-API libxml2 consumer for xml-fuzz.
 *
 * Exercises major public surfaces (aligned with fuzz/{xml,html,reader,xpath,
 * schema,regexp,uri,valid,xinclude} plus save/c14n/rng/tree):
 *
 *   --api=xml-memory|xml-push|xml-reader|xml-valid
 *   --api=html-memory|html-push
 *   --api=xpath|xpointer
 *   --api=schema-parse|schema-valid|rng-parse|rng-valid
 *   --api=regexp|uri|xinclude|save|c14n|catalog|tree
 *   --api=reader-ops|io-callback|reader-schema|reader-rng
 *   --api=all   (run every enabled API on the same input)
 *
 * Dual-document inputs use a split marker "\n---SPLIT---\n":
 *   - xpath:      DOC ---SPLIT--- EXPR
 *   - schema-valid / rng-valid / reader-schema / reader-rng:
 *                 SCHEMA ---SPLIT--- INSTANCE
 *   - reader-ops: optional OPS ---SPLIT--- DOC (else first bytes are ops)
 *
 * Stderr fingerprint lines: api= mode= root= text= text_len= elapsed_ms=
 * Exit: 0 accept-ish, 1 clean fail, 2 harness error
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlsave.h>
#include <libxml/uri.h>
#include <libxml/xmlerror.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xpointer.h>
#include <libxml/xmlregexp.h>
#include <libxml/xmlschemas.h>
#include <libxml/relaxng.h>
#include <libxml/xinclude.h>
#include <libxml/c14n.h>
#include <libxml/catalog.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/valid.h>

#define SPLIT_MARK "\n---SPLIT---\n"

static unsigned char *read_all(FILE *f, size_t *out_len) {
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len + 1024 > cap) {
            cap *= 2;
            unsigned char *n = realloc(buf, cap);
            if (!n) { free(buf); return NULL; }
            buf = n;
        }
        size_t n = fread(buf + len, 1, 1024, f);
        len += n;
        if (n < 1024) break;
    }
    *out_len = len;
    return buf;
}

static long ms_since(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0->tv_sec) * 1000L + (t1.tv_nsec - t0->tv_nsec) / 1000000L;
}

static void emit_text(const char *text) {
    size_t i = 0, out = 0;
    const size_t CAP = 4096;
    size_t raw = text ? strlen(text) : 0;
    fprintf(stderr, "text_len=%zu\ntext=", raw);
    if (!text) { fputc('\n', stderr); return; }
    while (text[i] && out < CAP) {
        unsigned char c = (unsigned char)text[i++];
        if (c == '\n') { fputs("\\n", stderr); out += 2; }
        else if (c == '\r') { fputs("\\r", stderr); out += 2; }
        else if (c == '\\') { fputs("\\\\", stderr); out += 2; }
        else if (c >= 32 && c < 127) { fputc(c, stderr); out++; }
        else { fprintf(stderr, "\\x%02x", c); out += 4; }
    }
    if (text[i]) fputs("...(trunc)", stderr);
    fputc('\n', stderr);
}

static void emit_hdr(const char *api, long elapsed) {
    fprintf(stderr, "api=%s\nelapsed_ms=%ld\n", api, elapsed);
}

static int split_two(const unsigned char *buf, size_t len,
                     const unsigned char **a, size_t *alen,
                     const unsigned char **b, size_t *blen) {
    size_t mlen = strlen(SPLIT_MARK);
    for (size_t i = 0; i + mlen <= len; i++) {
        if (memcmp(buf + i, SPLIT_MARK, mlen) == 0) {
            *a = buf; *alen = i;
            *b = buf + i + mlen; *blen = len - i - mlen;
            return 1;
        }
    }
    *a = buf; *alen = len; *b = NULL; *blen = 0;
    return 0;
}

static void discard_errors(void *ctx, const char *msg, ...) {
    (void)ctx; (void)msg;
}

/* ---------- API runners return 1 accept, 0 reject ---------- */

static int run_xml_memory(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;
    xmlDocPtr doc = xmlReadMemory((const char *)buf, (int)len, "fuzz.xml", NULL, opts);
    if (!doc) return 0;
    xmlNodePtr root = xmlDocGetRootElement(doc);
    fprintf(stderr, "mode=memory\nroot=%s\n", root && root->name ? (char *)root->name : "");
    xmlChar *t = root ? xmlNodeGetContent(root) : NULL;
    emit_text((const char *)t);
    if (t) xmlFree(t);
    xmlFreeDoc(doc);
    return 1;
}

static int run_xml_push(const unsigned char *buf, size_t len, int opts, int chunk) {
    if (chunk < 1) chunk = 17;
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, "fuzz.xml");
    if (!ctxt) return 0;
    if (opts) xmlCtxtUseOptions(ctxt, opts);
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > (size_t)chunk) n = (size_t)chunk;
        xmlParseChunk(ctxt, (const char *)buf + off, (int)n, 0);
        off += n;
    }
    xmlParseChunk(ctxt, NULL, 0, 1);
    int ok = ctxt->myDoc && ctxt->wellFormed;
    fprintf(stderr, "mode=push\nroot=%s\n",
            ctxt->myDoc && xmlDocGetRootElement(ctxt->myDoc) &&
            xmlDocGetRootElement(ctxt->myDoc)->name
                ? (char *)xmlDocGetRootElement(ctxt->myDoc)->name : "");
    if (ctxt->myDoc) {
        xmlChar *t = xmlNodeGetContent(xmlDocGetRootElement(ctxt->myDoc));
        emit_text((const char *)t);
        if (t) xmlFree(t);
        xmlFreeDoc(ctxt->myDoc);
    } else emit_text(NULL);
    xmlFreeParserCtxt(ctxt);
    return ok;
}

static int run_xml_reader(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;
    xmlTextReaderPtr r = xmlReaderForMemory((const char *)buf, (int)len, "fuzz.xml", NULL, opts);
    if (!r) { fprintf(stderr, "mode=reader\nroot=\n"); emit_text(NULL); return 0; }
    xmlBufferPtr acc = xmlBufferCreateSize(8192);
    const xmlChar *root = NULL;
    int ok = 1;
    while (1) {
        int rc = xmlTextReaderRead(r);
        if (rc != 1) { if (rc < 0) ok = 0; break; }
        int ty = xmlTextReaderNodeType(r);
        if (ty == XML_READER_TYPE_ELEMENT && !root)
            root = xmlTextReaderConstName(r);
        if (ty == XML_READER_TYPE_TEXT || ty == XML_READER_TYPE_CDATA) {
            const xmlChar *v = xmlTextReaderConstValue(r);
            if (v && acc) xmlBufferCat(acc, v);
        }
    }
    fprintf(stderr, "mode=reader\nroot=%s\n", root ? (const char *)root : "");
    emit_text(acc ? (const char *)xmlBufferContent(acc) : NULL);
    if (acc) xmlBufferFree(acc);
    xmlFreeTextReader(r);
    return ok && root != NULL;
}

/* Bounded reader op stream (simplified fuzz/reader.c). Max 200 ops. */
#define READER_OPS_MAX 200

static int run_reader_ops(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;

    const unsigned char *ops = buf;
    size_t nops = 0;
    const unsigned char *doc = buf;
    size_t dlen = len;

    const unsigned char *a, *b;
    size_t al, bl;
    if (split_two(buf, len, &a, &al, &b, &bl) && b && bl > 0) {
        ops = a;
        nops = al > READER_OPS_MAX ? READER_OPS_MAX : al;
        doc = b;
        dlen = bl;
    } else {
        /* No split: first min(32,len) bytes double as ops; full buf is document. */
        nops = len < 32 ? len : 32;
        if (nops > READER_OPS_MAX) nops = READER_OPS_MAX;
        ops = buf;
        doc = buf;
        dlen = len;
    }
    if (dlen > 0x7fffffff) return 0;

    xmlTextReaderPtr r = xmlReaderForMemory((const char *)doc, (int)dlen, "ops.xml", NULL, opts);
    fprintf(stderr, "mode=reader-ops\n");
    if (!r) {
        fprintf(stderr, "root=\n");
        emit_text(NULL);
        return 0;
    }

    const xmlChar *root = NULL;
    int n_done = 0;
    for (size_t i = 0; i < nops && n_done < READER_OPS_MAX; i++, n_done++) {
        int op = (int)(ops[i] % 24);
        switch (op) {
        case 0:
        default:
            xmlTextReaderRead(r);
            break;
        case 1:
            xmlTextReaderNext(r);
            break;
        case 2:
            xmlTextReaderNextSibling(r);
            break;
        case 3:
            xmlTextReaderMoveToFirstAttribute(r);
            break;
        case 4:
            xmlTextReaderMoveToNextAttribute(r);
            break;
        case 5:
            xmlTextReaderMoveToElement(r);
            break;
        case 6:
            xmlTextReaderReadAttributeValue(r);
            break;
        case 7:
            (void)xmlTextReaderConstValue(r);
            break;
        case 8:
            (void)xmlTextReaderConstName(r);
            break;
        case 9:
            (void)xmlTextReaderConstLocalName(r);
            break;
        case 10:
            (void)xmlTextReaderConstNamespaceUri(r);
            break;
        case 11:
            (void)xmlTextReaderConstPrefix(r);
            break;
        case 12:
            (void)xmlTextReaderAttributeCount(r);
            break;
        case 13:
            (void)xmlTextReaderDepth(r);
            break;
        case 14:
            (void)xmlTextReaderNodeType(r);
            break;
        case 15:
            (void)xmlTextReaderHasAttributes(r);
            break;
        case 16:
            (void)xmlTextReaderHasValue(r);
            break;
        case 17:
            (void)xmlTextReaderIsEmptyElement(r);
            break;
        case 18:
            (void)xmlTextReaderIsValid(r);
            break;
        case 19:
            (void)xmlTextReaderReadState(r);
            break;
        case 20:
            (void)xmlTextReaderByteConsumed(r);
            break;
        case 21: {
            xmlChar *s = xmlTextReaderReadString(r);
            if (s) xmlFree(s);
            break;
        }
        case 22: {
            /* Expand returns a node owned by the reader; do not free. */
            (void)xmlTextReaderExpand(r);
            break;
        }
        case 23: {
            xmlChar *inner = xmlTextReaderReadInnerXml(r);
            if (inner) xmlFree(inner);
            xmlChar *outer = xmlTextReaderReadOuterXml(r);
            if (outer) xmlFree(outer);
            break;
        }
        }
        if (!root && xmlTextReaderNodeType(r) == XML_READER_TYPE_ELEMENT)
            root = xmlTextReaderConstName(r);
    }

    /* Drain a few more reads so partial op streams still finish cleanly. */
    for (int k = 0; k < 32; k++) {
        int rc = xmlTextReaderRead(r);
        if (rc != 1) break;
        if (!root && xmlTextReaderNodeType(r) == XML_READER_TYPE_ELEMENT)
            root = xmlTextReaderConstName(r);
    }

    fprintf(stderr, "root=%s\n", root ? (const char *)root : "");
    char tmp[48];
    snprintf(tmp, sizeof(tmp), "ops=%d", n_done);
    emit_text(tmp);
    xmlFreeTextReader(r);
    return root != NULL;
}

/* Custom I/O: short reads + occasional early EOF via xmlReadIO / IO parser ctxt. */
typedef struct {
    const char *data;
    size_t size;
    size_t pos;
    unsigned call_n;
    unsigned short_mod; /* short-read modulus (1..32) */
    int early_eof_at;   /* call index for one early 0, or -1 */
} fuzz_io_state;

static int fuzz_io_read(void *context, char *buffer, int len) {
    fuzz_io_state *io = (fuzz_io_state *)context;
    if (!io || !buffer || len <= 0) return -1;
    if (io->pos >= io->size) return 0;

    io->call_n++;
    if (io->early_eof_at >= 0 && (int)io->call_n == io->early_eof_at && io->pos > 0)
        return 0; /* early EOF mid-stream */

    size_t remain = io->size - io->pos;
    size_t chunk = 1 + (size_t)((io->call_n + io->pos) % (io->short_mod ? io->short_mod : 1));
    if (chunk > (size_t)len) chunk = (size_t)len;
    if (chunk > remain) chunk = remain;
    if (chunk == 0) return 0;

    memcpy(buffer, io->data + io->pos, chunk);
    io->pos += chunk;
    return (int)chunk;
}

static int fuzz_io_close(void *context) {
    (void)context;
    return 0;
}

static int run_io_callback(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;

    /* Control bits from length only — full buffer remains the document. */
    unsigned mix = (unsigned)(len * 2654435761u);
    fuzz_io_state io;
    io.data = (const char *)buf;
    io.size = len;
    io.pos = 0;
    io.call_n = 0;
    io.short_mod = (mix % 31u) + 1u;
    /* Occasional early EOF mid-stream (deterministic on len). */
    io.early_eof_at = ((mix >> 8) & 0x7u) == 0u ? 5 : -1;

    int use_ctxt = (int)((mix >> 3) & 1u);
    fprintf(stderr, "mode=io-callback\n");

    int ok = 0;
    if (use_ctxt) {
        xmlParserCtxtPtr ctxt = xmlCreateIOParserCtxt(
            NULL, NULL, fuzz_io_read, fuzz_io_close, &io, XML_CHAR_ENCODING_NONE);
        if (!ctxt) {
            fprintf(stderr, "root=\n");
            emit_text(NULL);
            return 0;
        }
        if (opts) xmlCtxtUseOptions(ctxt, opts);
        xmlParseDocument(ctxt);
        ok = ctxt->myDoc != NULL && ctxt->wellFormed;
        fprintf(stderr, "root=%s\n",
                ctxt->myDoc && xmlDocGetRootElement(ctxt->myDoc) &&
                        xmlDocGetRootElement(ctxt->myDoc)->name
                    ? (char *)xmlDocGetRootElement(ctxt->myDoc)->name
                    : "");
        if (ctxt->myDoc) {
            xmlChar *t = xmlNodeGetContent(xmlDocGetRootElement(ctxt->myDoc));
            emit_text((const char *)t);
            if (t) xmlFree(t);
            xmlFreeDoc(ctxt->myDoc);
            ctxt->myDoc = NULL;
        } else {
            emit_text(NULL);
        }
        xmlFreeParserCtxt(ctxt);
    } else {
        xmlDocPtr doc = xmlReadIO(fuzz_io_read, fuzz_io_close, &io, "io.xml", NULL, opts);
        ok = doc != NULL;
        fprintf(stderr, "root=%s\n",
                doc && xmlDocGetRootElement(doc) && xmlDocGetRootElement(doc)->name
                    ? (char *)xmlDocGetRootElement(doc)->name
                    : "");
        if (doc) {
            xmlChar *t = xmlNodeGetContent(xmlDocGetRootElement(doc));
            emit_text((const char *)t);
            if (t) xmlFree(t);
            xmlFreeDoc(doc);
        } else {
            emit_text(NULL);
        }
    }
    return ok;
}

#if defined(LIBXML_SCHEMAS_ENABLED) && defined(LIBXML_READER_ENABLED)
static int run_reader_schema(const unsigned char *buf, size_t len, int opts) {
    const unsigned char *sb, *ib;
    size_t sl, il;
    fprintf(stderr, "mode=reader-schema\n");
    if (!split_two(buf, len, &sb, &sl, &ib, &il) || !ib) {
        fprintf(stderr, "root=\n");
        emit_text("no_split");
        return 0;
    }
    if (sl > 0x7fffffff || il > 0x7fffffff) return 0;

    xmlSchemaParserCtxtPtr pctxt =
        xmlSchemaNewMemParserCtxt((const char *)sb, (int)sl);
    if (!pctxt) {
        fprintf(stderr, "root=\n");
        emit_text("no_pctxt");
        return 0;
    }
    xmlSchemaSetParserStructuredErrors(pctxt, NULL, NULL);
    xmlSchemaPtr schema = xmlSchemaParse(pctxt);
    xmlSchemaFreeParserCtxt(pctxt);
    if (!schema) {
        fprintf(stderr, "root=\n");
        emit_text("no_schema");
        return 0;
    }

    xmlTextReaderPtr r =
        xmlReaderForMemory((const char *)ib, (int)il, "i.xml", NULL, opts);
    if (!r) {
        fprintf(stderr, "root=\n");
        emit_text("no_reader");
        xmlSchemaFree(schema);
        return 0;
    }
    if (xmlTextReaderSetSchema(r, schema) != 0) {
        fprintf(stderr, "root=\n");
        emit_text("set_schema_fail");
        xmlFreeTextReader(r);
        xmlSchemaFree(schema);
        return 0;
    }

    const xmlChar *root = NULL;
    int ok = 1;
    while (1) {
        int rc = xmlTextReaderRead(r);
        if (rc != 1) {
            if (rc < 0) ok = 0;
            break;
        }
        if (!root && xmlTextReaderNodeType(r) == XML_READER_TYPE_ELEMENT)
            root = xmlTextReaderConstName(r);
    }
    int valid = xmlTextReaderIsValid(r);
    fprintf(stderr, "root=%s\n", root ? (const char *)root : "");
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "valid=%d", valid);
    emit_text(tmp);
    /* Schema must outlive reader. */
    xmlFreeTextReader(r);
    xmlSchemaFree(schema);
    return ok && root != NULL;
}
#else
static int run_reader_schema(const unsigned char *buf, size_t len, int opts) {
    (void)buf; (void)len; (void)opts;
    fprintf(stderr, "mode=reader-schema\nroot=\n");
    emit_text("schemas_disabled");
    return 0;
}
#endif

#if defined(LIBXML_RELAXNG_ENABLED) && defined(LIBXML_READER_ENABLED)
static int run_reader_rng(const unsigned char *buf, size_t len, int opts) {
    const unsigned char *sb, *ib;
    size_t sl, il;
    fprintf(stderr, "mode=reader-rng\n");
    if (!split_two(buf, len, &sb, &sl, &ib, &il) || !ib) {
        fprintf(stderr, "root=\n");
        emit_text("no_split");
        return 0;
    }
    if (sl > 0x7fffffff || il > 0x7fffffff) return 0;

    xmlRelaxNGParserCtxtPtr pctxt =
        xmlRelaxNGNewMemParserCtxt((const char *)sb, (int)sl);
    if (!pctxt) {
        fprintf(stderr, "root=\n");
        emit_text("no_pctxt");
        return 0;
    }
    xmlRelaxNGPtr rng = xmlRelaxNGParse(pctxt);
    xmlRelaxNGFreeParserCtxt(pctxt);
    if (!rng) {
        fprintf(stderr, "root=\n");
        emit_text("no_rng");
        return 0;
    }

    xmlTextReaderPtr r =
        xmlReaderForMemory((const char *)ib, (int)il, "i.xml", NULL, opts);
    if (!r) {
        fprintf(stderr, "root=\n");
        emit_text("no_reader");
        xmlRelaxNGFree(rng);
        return 0;
    }
    if (xmlTextReaderRelaxNGSetSchema(r, rng) != 0) {
        fprintf(stderr, "root=\n");
        emit_text("set_rng_fail");
        xmlFreeTextReader(r);
        xmlRelaxNGFree(rng);
        return 0;
    }

    const xmlChar *root = NULL;
    int ok = 1;
    while (1) {
        int rc = xmlTextReaderRead(r);
        if (rc != 1) {
            if (rc < 0) ok = 0;
            break;
        }
        if (!root && xmlTextReaderNodeType(r) == XML_READER_TYPE_ELEMENT)
            root = xmlTextReaderConstName(r);
    }
    int valid = xmlTextReaderIsValid(r);
    fprintf(stderr, "root=%s\n", root ? (const char *)root : "");
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "valid=%d", valid);
    emit_text(tmp);
    xmlFreeTextReader(r);
    xmlRelaxNGFree(rng);
    return ok && root != NULL;
}
#else
static int run_reader_rng(const unsigned char *buf, size_t len, int opts) {
    (void)buf; (void)len; (void)opts;
    fprintf(stderr, "mode=reader-rng\nroot=\n");
    emit_text("rng_disabled");
    return 0;
}
#endif

static int run_xml_valid(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;
    opts |= XML_PARSE_DTDVALID | XML_PARSE_DTDLOAD | XML_PARSE_NOENT;
    xmlDocPtr doc = xmlReadMemory((const char *)buf, (int)len, "fuzz.xml", NULL, opts);
    fprintf(stderr, "mode=valid\nroot=%s\n",
            doc && xmlDocGetRootElement(doc) && xmlDocGetRootElement(doc)->name
                ? (char *)xmlDocGetRootElement(doc)->name : "");
    emit_text(NULL);
    int ok = doc != NULL;
    if (doc) xmlFreeDoc(doc);
    return ok;
}

#ifdef LIBXML_HTML_ENABLED
static int run_html_memory(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;
    htmlDocPtr doc = htmlReadMemory((const char *)buf, (int)len, "fuzz.html", NULL, opts);
    fprintf(stderr, "mode=html-memory\nroot=%s\n",
            doc && xmlDocGetRootElement(doc) && xmlDocGetRootElement(doc)->name
                ? (char *)xmlDocGetRootElement(doc)->name : "");
    if (doc) {
        xmlChar *t = xmlNodeGetContent(xmlDocGetRootElement(doc));
        emit_text((const char *)t);
        if (t) xmlFree(t);
        xmlFreeDoc(doc);
        return 1;
    }
    emit_text(NULL);
    return 0;
}

static int run_html_push(const unsigned char *buf, size_t len, int opts, int chunk) {
    if (chunk < 1) chunk = 17;
    htmlParserCtxtPtr ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0, "fuzz.html",
                                                      XML_CHAR_ENCODING_NONE);
    if (!ctxt) return 0;
    if (opts) htmlCtxtUseOptions(ctxt, opts);
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > (size_t)chunk) n = (size_t)chunk;
        htmlParseChunk(ctxt, (const char *)buf + off, (int)n, 0);
        off += n;
    }
    htmlParseChunk(ctxt, NULL, 0, 1);
    int ok = ctxt->myDoc != NULL;
    fprintf(stderr, "mode=html-push\nroot=%s\n",
            ctxt->myDoc && xmlDocGetRootElement(ctxt->myDoc) &&
                    xmlDocGetRootElement(ctxt->myDoc)->name
                ? (char *)xmlDocGetRootElement(ctxt->myDoc)->name
                : "");
    emit_text(NULL);
    if (ctxt->myDoc) xmlFreeDoc(ctxt->myDoc);
    htmlFreeParserCtxt(ctxt);
    return ok;
}
#endif

#ifdef LIBXML_XPATH_ENABLED
static int run_xpath(const unsigned char *buf, size_t len, int is_xptr) {
    const unsigned char *docb, *exprb;
    size_t docl, exprl;
    if (!split_two(buf, len, &docb, &docl, &exprb, &exprl) || !exprb) {
        /* default expression if no split */
        docb = buf; docl = len;
        exprb = (const unsigned char *)"//*";
        exprl = 3;
    }
    if (docl > 0x7fffffff || exprl > 0x7fffffff) return 0;
    char *expr = malloc(exprl + 1);
    if (!expr) return 0;
    memcpy(expr, exprb, exprl);
    expr[exprl] = 0;

    xmlDocPtr doc = xmlReadMemory((const char *)docb, (int)docl, "x.xml", NULL, XML_PARSE_RECOVER);
    fprintf(stderr, "mode=%s\n", is_xptr ? "xpointer" : "xpath");
    if (!doc) {
        fprintf(stderr, "root=\n");
        emit_text(NULL);
        free(expr);
        return 0;
    }
    xmlNodePtr root = xmlDocGetRootElement(doc);
    fprintf(stderr, "root=%s\n", root && root->name ? (char *)root->name : "");
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    int ok = 0;
    if (ctx) {
        ctx->opLimit = 500000;
        xmlXPathObjectPtr obj =
            is_xptr ? xmlXPtrEval(BAD_CAST expr, ctx)
                    : xmlXPathEvalExpression(BAD_CAST expr, ctx);
        ok = obj != NULL;
        if (obj) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "xpath_type=%d", obj->type);
            emit_text(tmp);
            xmlXPathFreeObject(obj);
        } else emit_text(NULL);
        xmlXPathFreeContext(ctx);
    } else emit_text(NULL);
    xmlFreeDoc(doc);
    free(expr);
    return ok;
}
#endif

#ifdef LIBXML_SCHEMAS_ENABLED
static int run_schema_parse(const unsigned char *buf, size_t len) {
    if (len > 0x7fffffff) return 0;
    xmlSchemaParserCtxtPtr pctxt =
        xmlSchemaNewMemParserCtxt((const char *)buf, (int)len);
    if (!pctxt) return 0;
    xmlSchemaSetParserStructuredErrors(pctxt, NULL, NULL);
    xmlSchemaPtr schema = xmlSchemaParse(pctxt);
    fprintf(stderr, "mode=schema-parse\nroot=\n");
    emit_text(schema ? "schema_ok" : "schema_fail");
    if (schema) xmlSchemaFree(schema);
    xmlSchemaFreeParserCtxt(pctxt);
    return schema != NULL;
}

static int run_schema_valid(const unsigned char *buf, size_t len) {
    const unsigned char *sb, *ib;
    size_t sl, il;
    if (!split_two(buf, len, &sb, &sl, &ib, &il) || !ib) return 0;
    if (sl > 0x7fffffff || il > 0x7fffffff) return 0;
    xmlSchemaParserCtxtPtr pctxt =
        xmlSchemaNewMemParserCtxt((const char *)sb, (int)sl);
    if (!pctxt) return 0;
    xmlSchemaPtr schema = xmlSchemaParse(pctxt);
    xmlSchemaFreeParserCtxt(pctxt);
    fprintf(stderr, "mode=schema-valid\nroot=\n");
    if (!schema) { emit_text("no_schema"); return 0; }
    xmlDocPtr doc = xmlReadMemory((const char *)ib, (int)il, "i.xml", NULL, 0);
    int ok = 0;
    if (doc) {
        xmlSchemaValidCtxtPtr v = xmlSchemaNewValidCtxt(schema);
        if (v) {
            ok = xmlSchemaValidateDoc(v, doc) == 0;
            xmlSchemaFreeValidCtxt(v);
        }
        xmlFreeDoc(doc);
    }
    emit_text(ok ? "valid" : "invalid");
    xmlSchemaFree(schema);
    return ok;
}
#endif

#ifdef LIBXML_SCHEMAS_ENABLED
static int run_rng_parse(const unsigned char *buf, size_t len) {
    if (len > 0x7fffffff) return 0;
    xmlRelaxNGParserCtxtPtr pctxt =
        xmlRelaxNGNewMemParserCtxt((const char *)buf, (int)len);
    if (!pctxt) return 0;
    xmlRelaxNGPtr rng = xmlRelaxNGParse(pctxt);
    fprintf(stderr, "mode=rng-parse\nroot=\n");
    emit_text(rng ? "rng_ok" : "rng_fail");
    if (rng) xmlRelaxNGFree(rng);
    xmlRelaxNGFreeParserCtxt(pctxt);
    return rng != NULL;
}

static int run_rng_valid(const unsigned char *buf, size_t len) {
    const unsigned char *sb, *ib;
    size_t sl, il;
    if (!split_two(buf, len, &sb, &sl, &ib, &il) || !ib) return 0;
    if (sl > 0x7fffffff || il > 0x7fffffff) return 0;
    xmlRelaxNGParserCtxtPtr pctxt =
        xmlRelaxNGNewMemParserCtxt((const char *)sb, (int)sl);
    if (!pctxt) return 0;
    xmlRelaxNGPtr rng = xmlRelaxNGParse(pctxt);
    xmlRelaxNGFreeParserCtxt(pctxt);
    fprintf(stderr, "mode=rng-valid\nroot=\n");
    if (!rng) { emit_text("no_rng"); return 0; }
    xmlDocPtr doc = xmlReadMemory((const char *)ib, (int)il, "i.xml", NULL, 0);
    int ok = 0;
    if (doc) {
        xmlRelaxNGValidCtxtPtr v = xmlRelaxNGNewValidCtxt(rng);
        if (v) {
            ok = xmlRelaxNGValidateDoc(v, doc) == 0;
            xmlRelaxNGFreeValidCtxt(v);
        }
        xmlFreeDoc(doc);
    }
    emit_text(ok ? "valid" : "invalid");
    xmlRelaxNGFree(rng);
    return ok;
}
#endif

#ifdef LIBXML_REGEXP_ENABLED
static int run_regexp(const unsigned char *buf, size_t len) {
    /* pattern ---SPLIT--- string */
    const unsigned char *pb, *sb;
    size_t pl, sl;
    if (!split_two(buf, len, &pb, &pl, &sb, &sl) || !sb) {
        pb = buf; pl = len; sb = (const unsigned char *)"x"; sl = 1;
    }
    char *pat = malloc(pl + 1);
    char *str = malloc(sl + 1);
    if (!pat || !str) { free(pat); free(str); return 0; }
    memcpy(pat, pb, pl); pat[pl] = 0;
    memcpy(str, sb, sl); str[sl] = 0;
    xmlRegexpPtr re = xmlRegexpCompile(BAD_CAST pat);
    fprintf(stderr, "mode=regexp\nroot=\n");
    int ok = 0;
    if (re) {
        ok = xmlRegexpExec(re, BAD_CAST str) == 1;
        xmlRegFreeRegexp(re);
        emit_text(ok ? "match" : "nomatch");
    } else emit_text("compile_fail");
    free(pat); free(str);
    return re != NULL;
}
#endif

static int run_uri(const unsigned char *buf, size_t len) {
    char *s = malloc(len + 1);
    if (!s) return 0;
    memcpy(s, buf, len); s[len] = 0;
    /* strip NULs for URI API */
    for (size_t i = 0; i < len; i++) if (s[i] == 0) s[i] = ' ';
    xmlURIPtr uri = xmlParseURI(s);
    fprintf(stderr, "mode=uri\nroot=\n");
    int ok = uri != NULL;
    if (uri) {
        xmlChar *saved = xmlSaveUri(uri);
        emit_text((const char *)saved);
        if (saved) xmlFree(saved);
        xmlFreeURI(uri);
    } else emit_text("uri_fail");
    /* also exercise escape / build */
    xmlChar *esc = xmlURIEscapeStr(BAD_CAST s, BAD_CAST "/:@");
    if (esc) xmlFree(esc);
    free(s);
    return ok;
}

#ifdef LIBXML_XINCLUDE_ENABLED
static int run_xinclude(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;
    xmlDocPtr doc = xmlReadMemory((const char *)buf, (int)len, "xi.xml", NULL,
                                  opts | XML_PARSE_XINCLUDE);
    fprintf(stderr, "mode=xinclude\nroot=%s\n",
            doc && xmlDocGetRootElement(doc) && xmlDocGetRootElement(doc)->name
                ? (char *)xmlDocGetRootElement(doc)->name : "");
    int ok = 0;
    if (doc) {
        ok = xmlXIncludeProcess(doc) >= 0;
        xmlChar *t = xmlNodeGetContent(xmlDocGetRootElement(doc));
        emit_text((const char *)t);
        if (t) xmlFree(t);
        xmlFreeDoc(doc);
    } else emit_text(NULL);
    return ok;
}
#endif

#ifdef LIBXML_OUTPUT_ENABLED
static int run_save(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;
    xmlDocPtr doc = xmlReadMemory((const char *)buf, (int)len, "s.xml", NULL, opts | XML_PARSE_RECOVER);
    fprintf(stderr, "mode=save\nroot=%s\n",
            doc && xmlDocGetRootElement(doc) && xmlDocGetRootElement(doc)->name
                ? (char *)xmlDocGetRootElement(doc)->name : "");
    int ok = 0;
    if (doc) {
        xmlBufferPtr out = xmlBufferCreate();
        xmlSaveCtxtPtr save = xmlSaveToBuffer(out, "UTF-8", 0);
        if (save) {
            xmlSaveDoc(save, doc);
            xmlSaveClose(save);
            emit_text((const char *)xmlBufferContent(out));
            ok = xmlBufferLength(out) > 0;
        } else emit_text(NULL);
        xmlBufferFree(out);
        xmlFreeDoc(doc);
    } else emit_text(NULL);
    return ok;
}
#endif

#ifdef LIBXML_C14N_ENABLED
static int run_c14n(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;
    xmlDocPtr doc = xmlReadMemory((const char *)buf, (int)len, "c.xml", NULL, opts | XML_PARSE_RECOVER);
    fprintf(stderr, "mode=c14n\nroot=%s\n",
            doc && xmlDocGetRootElement(doc) && xmlDocGetRootElement(doc)->name
                ? (char *)xmlDocGetRootElement(doc)->name : "");
    int ok = 0;
    if (doc) {
        xmlChar *out = NULL;
        int outlen = 0;
        ok = xmlC14NDocDumpMemory(doc, NULL, XML_C14N_1_0, NULL, 0, &out) >= 0;
        if (out) {
            emit_text((const char *)out);
            xmlFree(out);
        } else emit_text(NULL);
        (void)outlen;
        xmlFreeDoc(doc);
    } else emit_text(NULL);
    return ok;
}
#endif

#ifdef LIBXML_CATALOG_ENABLED
static int run_catalog(const unsigned char *buf, size_t len) {
    /* Treat input as catalog document text */
    if (len > 0x7fffffff) return 0;
    char *tmp = malloc(len + 1);
    if (!tmp) return 0;
    memcpy(tmp, buf, len); tmp[len] = 0;
    /* write temp catalog */
    char path[] = "/tmp/xmlfuzz_cat_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { free(tmp); return 0; }
    write(fd, tmp, len);
    close(fd);
    free(tmp);
    xmlCatalogPtr cat = xmlLoadACatalog(path);
    fprintf(stderr, "mode=catalog\nroot=\n");
    int ok = cat != NULL;
    emit_text(ok ? "catalog_ok" : "catalog_fail");
    if (cat) {
        xmlChar *res = xmlCatalogResolvePublic(BAD_CAST "-//TEST//DTD Test//EN");
        if (res) xmlFree(res);
        xmlACatalogDump(cat, NULL);
        xmlFreeCatalog(cat);
    }
    unlink(path);
    return ok;
}
#endif

static int run_tree(const unsigned char *buf, size_t len, int opts) {
    if (len > 0x7fffffff) return 0;
    xmlDocPtr doc = xmlReadMemory((const char *)buf, (int)len, "t.xml", NULL, opts | XML_PARSE_RECOVER);
    fprintf(stderr, "mode=tree\nroot=%s\n",
            doc && xmlDocGetRootElement(doc) && xmlDocGetRootElement(doc)->name
                ? (char *)xmlDocGetRootElement(doc)->name : "");
    int ok = 0;
    if (doc) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root) {
            xmlNodePtr copy = xmlCopyNode(root, 1);
            if (copy) {
                xmlNodePtr kid = xmlNewDocNode(doc, NULL, BAD_CAST "fuzzchild", BAD_CAST "v");
                if (kid) xmlAddChild(root, kid);
                xmlUnlinkNode(copy);
                xmlFreeNode(copy);
            }
            xmlChar *t = xmlNodeGetContent(root);
            emit_text((const char *)t);
            if (t) xmlFree(t);
            ok = 1;
        } else emit_text(NULL);
        xmlFreeDoc(doc);
    } else emit_text(NULL);
    return ok;
}

static int dispatch(const char *api, const unsigned char *buf, size_t len,
                    int opts, int chunk) {
    if (!strcmp(api, "xml-memory")) return run_xml_memory(buf, len, opts);
    if (!strcmp(api, "xml-push")) return run_xml_push(buf, len, opts, chunk);
    if (!strcmp(api, "xml-reader")) return run_xml_reader(buf, len, opts);
    if (!strcmp(api, "xml-valid")) return run_xml_valid(buf, len, opts);
    if (!strcmp(api, "reader-ops")) return run_reader_ops(buf, len, opts);
    if (!strcmp(api, "io-callback")) return run_io_callback(buf, len, opts);
    if (!strcmp(api, "reader-schema")) return run_reader_schema(buf, len, opts);
    if (!strcmp(api, "reader-rng")) return run_reader_rng(buf, len, opts);
#ifdef LIBXML_HTML_ENABLED
    if (!strcmp(api, "html-memory")) return run_html_memory(buf, len, opts);
    if (!strcmp(api, "html-push")) return run_html_push(buf, len, opts, chunk);
#endif
#ifdef LIBXML_XPATH_ENABLED
    if (!strcmp(api, "xpath")) return run_xpath(buf, len, 0);
    if (!strcmp(api, "xpointer")) return run_xpath(buf, len, 1);
#endif
#ifdef LIBXML_SCHEMAS_ENABLED
    if (!strcmp(api, "schema-parse")) return run_schema_parse(buf, len);
    if (!strcmp(api, "schema-valid")) return run_schema_valid(buf, len);
    if (!strcmp(api, "rng-parse")) return run_rng_parse(buf, len);
    if (!strcmp(api, "rng-valid")) return run_rng_valid(buf, len);
#endif
#ifdef LIBXML_REGEXP_ENABLED
    if (!strcmp(api, "regexp")) return run_regexp(buf, len);
#endif
    if (!strcmp(api, "uri")) return run_uri(buf, len);
#ifdef LIBXML_XINCLUDE_ENABLED
    if (!strcmp(api, "xinclude")) return run_xinclude(buf, len, opts);
#endif
#ifdef LIBXML_OUTPUT_ENABLED
    if (!strcmp(api, "save")) return run_save(buf, len, opts);
#endif
#ifdef LIBXML_C14N_ENABLED
    if (!strcmp(api, "c14n")) return run_c14n(buf, len, opts);
#endif
#ifdef LIBXML_CATALOG_ENABLED
    if (!strcmp(api, "catalog")) return run_catalog(buf, len);
#endif
    if (!strcmp(api, "tree")) return run_tree(buf, len, opts);
    fprintf(stderr, "unknown api=%s\n", api);
    return 0;
}

static const char *ALL_APIS[] = {
    "xml-memory", "xml-push", "xml-reader", "xml-valid",
    "html-memory", "html-push",
    "xpath", "xpointer",
    "schema-parse", "schema-valid", "rng-parse", "rng-valid",
    "regexp", "uri", "xinclude", "save", "c14n", "catalog", "tree",
    "reader-ops", "io-callback", "reader-schema", "reader-rng",
    NULL
};

int main(int argc, char **argv) {
    const char *api = "xml-memory";
    const char *path = NULL;
    int opts = 0, chunk = 17, do_all = 0;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--api=", 6)) api = argv[i] + 6;
        else if (!strcmp(argv[i], "--all")) do_all = 1;
        else if (!strcmp(argv[i], "--noent")) opts |= XML_PARSE_NOENT;
        else if (!strcmp(argv[i], "--dtdload")) opts |= XML_PARSE_DTDLOAD;
        else if (!strcmp(argv[i], "--dtdattr")) opts |= XML_PARSE_DTDATTR;
        else if (!strcmp(argv[i], "--huge")) opts |= XML_PARSE_HUGE;
        else if (!strcmp(argv[i], "--nonet")) opts |= XML_PARSE_NONET;
        else if (!strcmp(argv[i], "--xinclude")) opts |= XML_PARSE_XINCLUDE;
        else if (!strcmp(argv[i], "--recover")) opts |= XML_PARSE_RECOVER;
        else if (!strcmp(argv[i], "--no-xxe")) opts |= XML_PARSE_NO_XXE;
        else if (!strncmp(argv[i], "--chunk=", 8)) chunk = atoi(argv[i] + 8);
        else path = argv[i];
    }
    if (chunk < 1) chunk = 1;

    FILE *in = path ? fopen(path, "rb") : stdin;
    if (!in) return 2;
    size_t len = 0;
    unsigned char *buf = read_all(in, &len);
    if (path) fclose(in);
    if (!buf) return 2;

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, discard_errors);

    int any_ok = 0;
    if (do_all || !strcmp(api, "all")) {
        for (int i = 0; ALL_APIS[i]; i++) {
            fprintf(stderr, "--- begin %s ---\n", ALL_APIS[i]);
            emit_hdr(ALL_APIS[i], 0);
            int ok = dispatch(ALL_APIS[i], buf, len, opts, chunk);
            fprintf(stderr, "result=%s\n", ok ? "ok" : "fail");
            if (ok) any_ok = 1;
        }
        emit_hdr("all", ms_since(&t0));
    } else {
        emit_hdr(api, 0);
        any_ok = dispatch(api, buf, len, opts, chunk);
        fprintf(stderr, "elapsed_ms=%ld\n", ms_since(&t0));
    }

    free(buf);
    xmlCleanupParser();
    return any_ok ? 0 : 1;
}
