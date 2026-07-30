/*
 * Thin libxml2 consumer for xml-fuzz-produced documents.
 *
 * Reads one document from stdin (or a path argument) and parses via
 * xmlReadMemory / push / reader. Exit codes:
 *   0 — accepted document
 *   1 — clean parse failure
 *   2 — usage / I/O error
 *   3 — timed out internally (should be rare; parent also kills)
 *
 * Stderr fingerprint (machine-readable, one key per line):
 *   root=<name>
 *   text=<document text content, newlines as \\n, max ~4KiB>
 *   elapsed_ms=<wall ms>
 *   mode=<memory|push|reader>
 *   text_len=<byte length before truncate>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlreader.h>

static unsigned char *read_all(FILE *f, size_t *out_len) {
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return NULL;
    while (1) {
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

/* Escape text for single-line stderr: replace \n \r with visible escapes; cap size. */
static void emit_text_fingerprint(const xmlChar *text) {
    const size_t CAP = 4096;
    size_t i = 0, out = 0;
    if (!text) {
        fprintf(stderr, "text_len=0\n");
        fprintf(stderr, "text=\n");
        return;
    }
    size_t raw_len = xmlStrlen(text);
    fprintf(stderr, "text_len=%zu\n", raw_len);
    fprintf(stderr, "text=");
    while (text[i] != 0 && out < CAP) {
        unsigned char c = text[i++];
        if (c == '\n') {
            fputs("\\n", stderr);
            out += 2;
        } else if (c == '\r') {
            fputs("\\r", stderr);
            out += 2;
        } else if (c == '\\') {
            fputs("\\\\", stderr);
            out += 2;
        } else if (c >= 32 && c < 127) {
            fputc(c, stderr);
            out++;
        } else {
            fprintf(stderr, "\\x%02x", c);
            out += 4;
        }
    }
    if (text[i] != 0)
        fputs("...(trunc)", stderr);
    fputc('\n', stderr);
}

static void emit_doc_fingerprint(xmlDocPtr doc, const char *mode, long elapsed_ms) {
    xmlNodePtr root = doc ? xmlDocGetRootElement(doc) : NULL;
    fprintf(stderr, "mode=%s\n", mode);
    fprintf(stderr, "elapsed_ms=%ld\n", elapsed_ms);
    if (root && root->name)
        fprintf(stderr, "root=%s\n", root->name);
    else
        fprintf(stderr, "root=\n");
    if (root) {
        xmlChar *content = xmlNodeGetContent(root);
        emit_text_fingerprint(content);
        if (content) xmlFree(content);
    } else {
        fprintf(stderr, "text_len=0\n");
        fprintf(stderr, "text=\n");
    }
}

static long ms_since(struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0->tv_sec) * 1000L + (t1.tv_nsec - t0->tv_nsec) / 1000000L;
}

int main(int argc, char **argv) {
    const char *mode = "memory";
    const char *path = NULL;
    int options = 0;
    int chunk_size = 17;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--push") == 0) mode = "push";
        else if (strcmp(argv[i], "--reader") == 0) mode = "reader";
        else if (strcmp(argv[i], "--noent") == 0) options |= XML_PARSE_NOENT;
        else if (strcmp(argv[i], "--dtdload") == 0) options |= XML_PARSE_DTDLOAD;
        else if (strcmp(argv[i], "--dtdattr") == 0) options |= XML_PARSE_DTDATTR;
        else if (strcmp(argv[i], "--huge") == 0) options |= XML_PARSE_HUGE;
        else if (strcmp(argv[i], "--nonet") == 0) options |= XML_PARSE_NONET;
        else if (strcmp(argv[i], "--xinclude") == 0) options |= XML_PARSE_XINCLUDE;
        else if (strcmp(argv[i], "--recover") == 0) options |= XML_PARSE_RECOVER;
        else if (strcmp(argv[i], "--no-xxe") == 0) options |= XML_PARSE_NO_XXE;
        else if (strncmp(argv[i], "--chunk=", 8) == 0) chunk_size = atoi(argv[i] + 8);
        else path = argv[i];
    }
    if (chunk_size < 1) chunk_size = 1;

    FILE *in = path ? fopen(path, "rb") : stdin;
    if (!in) {
        fprintf(stderr, "open failed\n");
        return 2;
    }
    size_t len = 0;
    unsigned char *buf = read_all(in, &len);
    if (path) fclose(in);
    if (!buf) return 2;

    /* int-size API: reject absurd lengths for this harness */
    if (len > (size_t)0x7fffffff) {
        free(buf);
        fprintf(stderr, "input too large\n");
        return 2;
    }

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    xmlInitParser();
    int accepted = 0;
    xmlDocPtr doc = NULL;

    if (strcmp(mode, "push") == 0) {
        xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, "fuzz.xml");
        if (!ctxt) { free(buf); return 2; }
        if (options) xmlCtxtUseOptions(ctxt, options);
        size_t off = 0;
        while (off < len) {
            size_t remain = len - off;
            int chunk = (int)(remain > (size_t)chunk_size ? (size_t)chunk_size : remain);
            xmlParseChunk(ctxt, (const char *)buf + off, chunk, 0);
            off += (size_t)chunk;
        }
        xmlParseChunk(ctxt, NULL, 0, 1);
        accepted = ctxt->myDoc != NULL && ctxt->wellFormed;
        doc = ctxt->myDoc;
        ctxt->myDoc = NULL; /* steal */
        xmlFreeParserCtxt(ctxt);
        if (doc)
            emit_doc_fingerprint(doc, "push", ms_since(&t0));
        else {
            fprintf(stderr, "mode=push\nelapsed_ms=%ld\nroot=\ntext_len=0\ntext=\n", ms_since(&t0));
        }
    } else if (strcmp(mode, "reader") == 0) {
        /*
         * Streaming reader: walk all nodes and accumulate text-ish content for
         * fingerprint (entity expansion shows up in text nodes when expanded).
         */
        xmlTextReaderPtr reader = xmlReaderForMemory((const char *)buf, (int)len,
                                                     "fuzz.xml", NULL, options);
        if (!reader) {
            fprintf(stderr, "mode=reader\nelapsed_ms=%ld\nroot=\ntext_len=0\ntext=\n",
                    ms_since(&t0));
            free(buf);
            xmlCleanupParser();
            return 1;
        }
        xmlBufferPtr acc = xmlBufferCreateSize(8192);
        const xmlChar *root_name = NULL;
        int ok = 1;
        while (1) {
            int rc = xmlTextReaderRead(reader);
            if (rc != 1) {
                if (rc < 0) ok = 0;
                break;
            }
            int type = xmlTextReaderNodeType(reader);
            if (type == XML_READER_TYPE_ELEMENT && root_name == NULL) {
                root_name = xmlTextReaderConstLocalName(reader);
                if (!root_name) root_name = xmlTextReaderConstName(reader);
            }
            if (type == XML_READER_TYPE_TEXT || type == XML_READER_TYPE_CDATA ||
                type == XML_READER_TYPE_SIGNIFICANT_WHITESPACE) {
                const xmlChar *v = xmlTextReaderConstValue(reader);
                if (v && acc) xmlBufferCat(acc, v);
            }
        }
        long elapsed = ms_since(&t0);
        fprintf(stderr, "mode=reader\n");
        fprintf(stderr, "elapsed_ms=%ld\n", elapsed);
        fprintf(stderr, "root=%s\n", root_name ? (const char *)root_name : "");
        emit_text_fingerprint(acc ? xmlBufferContent(acc) : NULL);
        accepted = ok && root_name != NULL;
        if (acc) xmlBufferFree(acc);
        xmlFreeTextReader(reader);
    } else {
        doc = xmlReadMemory((const char *)buf, (int)len, "fuzz.xml", NULL, options);
        accepted = doc != NULL;
        if (doc)
            emit_doc_fingerprint(doc, "memory", ms_since(&t0));
        else {
            fprintf(stderr, "mode=memory\nelapsed_ms=%ld\nroot=\ntext_len=0\ntext=\n",
                    ms_since(&t0));
        }
    }

    if (doc) xmlFreeDoc(doc);
    free(buf);
    xmlCleanupParser();
    return accepted ? 0 : 1;
}
