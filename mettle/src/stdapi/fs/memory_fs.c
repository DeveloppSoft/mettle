#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mettle.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"

enum NodeType {
    Directory,
    File
};

typedef struct {
    char *key;
    void *value;
} Entry;

typedef struct {
    Node *parent;
    char *name;
    
    enum NodeType node_type;
    
    // Directory
    uint nb_entries;
    Entry *entries;
    
    // File
    uint seek_offset;
    uint size;
    void *buf;
} Node;

Node root_node;
Node *at;

// Command ideas:
// -  exec
// -  play
// -  send to target fs

// TODO
int memory_chdir(char *path);
int memory_rm(char *path);
int memory_move(char *src, char *dst);
int memory_copy(char *src, char *dst);
int memory_getwd(char *dst, uint len);
int memory_mkdir(char *path);
int memory_rmdir(char *path);

Node *memory_at(char *path);

struct tlv_packet *fs_chdir(struct tlv_handler_ctx *ctx) {
    const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
    if (path == NULL) {
        return tlv_packet_response_result(ctx, EINVAL);
    }
    
    int rc = TLV_RESULT_SUCCESS;
    if (memory_chdir(path) == -1) {
        rc = TLV_RESULT_FAILURE;
    }
    
    return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *fs_delete_file(struct tlv_handler_ctx *ctx) {
    const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
    if (path == NULL) {
        return tlv_packet_response_result(ctx, EINVAL);
    }
    
    int rc = TLV_RESULT_SUCCESS;
    if (memory_rm(path) == -1) {
        rc = TLV_RESULT_FAILURE;
    }
    
    return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *fs_expand_path(struct tlv_handler_ctx *ctx) {
    const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
    if (path == NULL) {
        return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
    }
    
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    return tlv_packet_add_str(p, TLV_TYPE_FILE_PATH, path);
}

struct tlv_packet *fs_file_move(struct tlv_handler_ctx *ctx) {
    const char *src = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_NAME);
    const char *dst = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
    
    if (src == NULL || dst == NULL) {
        return tlv_packet_response_result(ctx, EINVAL);
    }
    
    int rc = TLV_RESULT_SUCCESS;
    if (memory_move(src, dst) == -1) {
        rc = TLV_RESULT_FAILURE;
    }
    
    return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *fs_file_copy(struct tlv_handler_ctx *ctx) {
    const char *src = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_NAME);
    const char *dst = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
    
    int rc = TLV_RESULT_SUCCESS;
    
    if (src == NULL || dst == NULL) {
        rc = EINVAL;
    } else if (memory_copy(src, dst) == -1) {
        rc = TLV_RESULT_FAILURE;
    }

    return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *fs_getwd(struct tlv_handler_ctx *ctx) {
    char dir[PATH_MAX];
    if (memory_getcwd(dir, sizeof(dir)) == NULL) {
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }
    
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    return tlv_packet_add_str(p, TLV_TYPE_DIRECTORY_PATH, dir);
}

struct tlv_packet *fs_mkdir(struct tlv_handler_ctx *ctx) {
    const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
    if (path == NULL) {
        return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
    }
    
    int rc = TLV_RESULT_SUCCESS;
    if (memory_mkdir(path) == -1) {
        rc = TLV_RESULT_SUCCESS;
    }
    
    return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *fs_rmdir(struct tlv_handler_ctx *ctx)
{
    const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
    if (path == NULL) {
        return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
    }
    
    int rc = TLV_RESULT_SUCCESS;
    if (memory_rmdir(path) == -1) {
        rc = TLV_RESULT_SUCCESS;
    }
    
    return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *fs_ls(struct tlv_handler_ctx *ctx) {
    const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
    if (path == NULL) {
        return tlv_packet_response_result(ctx, EINVAL);
    }

    Node *target = memory_at(path);
    if (target == NULL || Node->type != Directory) {
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }
    
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    
    for (int i = 0; i < target->nb_entries; i++) {
        char fq_path[PATH_MAX];
        snprintf(fq_path, sizeof(fq_path), "%s/%s", path, target->name);
        p = tlv_packet_add_str(p, TLV_TYPE_FILE_NAME, name);
        p = tlv_packet_add_str(p, TLV_TYPE_FILE_PATH, fq_path);
    }

    return p;
}

struct tlv_packet *fs_separator(struct tlv_handler_ctx *ctx) {
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    return tlv_packet_add_str(p, TLV_TYPE_STRING, "/");
}

struct tlv_packet *fs_stat(struct tlv_handler_ctx *ctx) {
    if (path == NULL) {
        return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
    }
    
    Node *target = memory_at(path);
    if (target == NULL || Node->type != File) {
        return return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }
    
    struct meterp_stat {
        uint32_t dev;
        uint16_t ino;
        uint16_t mode;
        uint16_t nlink;
        uint16_t uid;
        uint16_t gid;
        uint16_t pad;
        uint32_t rdev;
        uint32_t size;
        uint64_t atime;
        uint64_t mtime;
        uint64_t ctime;
    } ms = {
        .dev = 0,
        .ino = 0,
        .mode = 0,
        .nlink = 0,
        .uid = 0,
        .gid = 0,
        .rdev = 0,
        .size = Node->size,
    };

    p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    return tlv_packet_add_raw(p, TLV_TYPE_STAT_BUF, &ms, sizeof(ms));
}

int file_new(struct tlv_handler_ctx *ctx, struct channel *c) {
    char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
    char *mode = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_MODE);
    if (mode == NULL) {
        mode = "rb";
    }
    
    // TODO
    
    channel_set_ctx(c, f);
    return 0;
}

ssize_t file_read(struct channel *c, void *buf, size_t len) {
    //FILE *f = channel_get_ctx(c);
    return 0; // TODO
}

ssize_t file_write(struct channel *c, void *buf, size_t len) {
    //FILE *f = channel_get_ctx(c);
    return 0; // TODO
}

int file_seek(struct channel *c, ssize_t offset, int whence) {
    //FILE *f = channel_get_ctx(c);
    return 0; // TODO
}

bool file_eof(struct channel *c) {
    //FILE *f = channel_get_ctx(c);
    return false; // TODO
}

int file_free(struct channel *c) {
    //FILE *f = channel_get_ctx(c);
    return 0; // TODO
}

void memory_fs_register_handlers(struct mettle *m) {
    root_node.parent = NULL;
    root_node.name = "";
    root_node.node_type = Directory;
    root_node.nb_entries = 0;
    root_node.entries = NULL;
    
    at = &root_node;
    
    struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
    struct channelmgr *cm = mettle_get_channelmgr(m);
    
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_chdir", fs_chdir, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_delete_file", fs_delete_file, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_file_expand_path", fs_expand_path, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_file_move", fs_file_move, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_file_copy", fs_file_copy, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_getwd", fs_getwd, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_mkdir", fs_mkdir, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_delete_dir", fs_rmdir, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_ls", fs_ls, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_separator", fs_separator, m);
    tlv_dispatcher_add_handler(td, "stdapi_memory_fs_stat", fs_stat, m);
    //tlv_dispatcher_add_handler(td, "stdapi_memory_fs_md5", fs_md5, m);
    //tlv_dispatcher_add_handler(td, "stdapi_mempry_fs_sha1", fs_sha1, m);
    
    struct channel_callbacks cbs = {
        .new_cb = file_new,
        .read_cb = file_read,
        .write_cb = file_write,
        .eof_cb = file_eof,
        .seek_cb = file_seek,
        .free_cb = file_free,
    };
    channelmgr_add_channel_type(cm, "stdapi_memory_fs_file", &cbs);
}
