#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include "blazesym.h"
#include "blazesym_api.h"

#define MAX_MODULES 256
#define MAX_LINE 512

typedef struct
{
    uint64_t start;
    uint64_t end;
    uint64_t file_offset;
    char path[256];
} module_t;

/* ========== 全局缓存 ========== */

static module_t g_modules[MAX_MODULES];
static int g_mod_cnt = 0;
static pid_t g_cached_pid = -1;

static char g_binary_path[256] = {0};
static uint64_t g_binary_base = 0;
static long g_binary_size = 0;
static int g_binary_loaded = 0;

static int load_modules_from_proc(int pid)
{
    if (pid == g_cached_pid && g_mod_cnt > 0)
        return g_mod_cnt;

    g_cached_pid = pid;
    g_mod_cnt = 0;

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp)
        return 0;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp) && g_mod_cnt < MAX_MODULES)
    {
        uint64_t start, end;
        char perms[8], fpath[256] = {0};
        unsigned long long off;
        unsigned int maj, min;
        unsigned long inode;

        int n = sscanf(line, "%lx-%lx %7s %llx %x:%x %lu %255s",
                       &start, &end, perms, &off, &maj, &min, &inode, fpath);
        if (n < 6)
            continue;
        if (inode == 0 || fpath[0] == '\0')
            continue;
        if (perms[2] != 'x')
            continue;

        int dup = 0;
        for (int j = 0; j < g_mod_cnt; j++)
        {
            if (strcmp(g_modules[j].path, fpath) == 0)
            {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;

        g_modules[g_mod_cnt].start = start;
        g_modules[g_mod_cnt].end = end;
        g_modules[g_mod_cnt].file_offset = off;
        strncpy(g_modules[g_mod_cnt].path, fpath,
                sizeof(g_modules[g_mod_cnt].path) - 1);
        g_mod_cnt++;
    }
    fclose(fp);
    return g_mod_cnt;
}

static int resolve_from_maps(const uint64_t *addrs, size_t addr_cnt,
                             sym_info_t *results)
{
    if (g_mod_cnt == 0)
        return 0;

    int any = 0;

    struct blaze_symbolizer_opts sym_opts = {
        .type_size = sizeof(sym_opts),
        .code_info = true,
        .inlined_fns = true,
    };
    blaze_symbolizer *sym = blaze_symbolizer_new_opts(&sym_opts);
    if (!sym)
        return 0;

    for (int m = 0; m < g_mod_cnt; m++)
    {
        uint64_t mod_addrs[128];
        int mod_addr_idx[128];
        int mod_addr_cnt = 0;

        for (size_t i = 0; i < addr_cnt && mod_addr_cnt < 128; i++)
        {
            if (results[i].name[0] != '\0')
                continue;
            if (addrs[i] >= g_modules[m].start &&
                addrs[i] < g_modules[m].end)
            {
                uint64_t base = g_modules[m].start - g_modules[m].file_offset;
                mod_addrs[mod_addr_cnt] = addrs[i] - base;
                mod_addr_idx[mod_addr_cnt] = (int)i;
                mod_addr_cnt++;
            }
        }

        if (mod_addr_cnt == 0)
            continue;

        struct blaze_symbolize_src_elf src = {
            .type_size = sizeof(src),
            .path = g_modules[m].path,
            .debug_syms = true,
        };

        const struct blaze_syms *syms =
            blaze_symbolize_elf_virt_offsets(sym, &src, mod_addrs, mod_addr_cnt);

        if (!syms)
            continue;

        for (int k = 0; k < (int)syms->cnt && k < mod_addr_cnt; k++)
        {
            int idx = mod_addr_idx[k];
            const struct blaze_sym *s = &syms->syms[k];

            if (s->name)
                strncpy(results[idx].name, s->name,
                        sizeof(results[idx].name) - 1);
            if (s->module)
                strncpy(results[idx].module, s->module,
                        sizeof(results[idx].module) - 1);
            else
            {
                strncpy(results[idx].module, g_modules[m].path,
                        sizeof(results[idx].module) - 1);
                results[idx].module_offset = mod_addrs[k];
            }
            if (s->offset)
                results[idx].module_offset = s->offset;

            if (s->code_info.file)
            {
                strncpy(results[idx].src_path, s->code_info.file,
                        sizeof(results[idx].src_path) - 1);
                results[idx].src_line = s->code_info.line;
            }
            any = 1;
        }
        blaze_syms_free(syms);
    }

    blaze_symbolizer_free(sym);
    return any;
}

static int resolve_from_binary(const char *comm, uint64_t load_base,
                               const uint64_t *addrs, size_t addr_cnt,
                               sym_info_t *results)
{
    if (g_binary_loaded == 0)
    {
        snprintf(g_binary_path, sizeof(g_binary_path), "./%s", comm);
        if (access(g_binary_path, R_OK) != 0)
        {
            g_binary_loaded = -1;
            return 0;
        }
        if (load_base == 0)
        {
            g_binary_loaded = -1;
            return 0;
        }
        g_binary_base = load_base;

        // FILE *fp = fopen(g_binary_path, "rb");
        // if (fp) {
        //     fseek(fp, 0, SEEK_END);
        //     g_binary_size = ftell(fp);
        //     fclose(fp);
        // }
        g_binary_loaded = 1;
    }

    if (g_binary_loaded < 0)
        return 0;

    struct blaze_symbolizer_opts sym_opts = {
        .type_size = sizeof(sym_opts),
        .code_info = true,
        .inlined_fns = true,
    };
    blaze_symbolizer *sym = blaze_symbolizer_new_opts(&sym_opts);
    if (!sym)
        return 0;

    uint64_t virt_offsets[128];
    int virt_idx[128];
    int virt_cnt = 0;
    for (size_t i = 0; i < addr_cnt && virt_cnt < 128; i++)
    {
        uint64_t vo = addrs[i] - g_binary_base;
        // if (g_binary_size > 0 && vo >= (uint64_t)g_binary_size)// 超出二进制大小
        //     continue;
        virt_offsets[virt_cnt] = vo;
        virt_idx[virt_cnt] = (int)i;
        results[i].module_offset = vo;
        strncpy(results[i].module, g_binary_path,
                sizeof(results[i].module) - 1);
        virt_cnt++;
    }

    int any = 0;

    struct blaze_symbolize_src_elf src = {
        .type_size = sizeof(src),
        .path = g_binary_path,
        .debug_syms = true,
    };

    const struct blaze_syms *syms =
        blaze_symbolize_elf_virt_offsets(sym, &src, virt_offsets, virt_cnt);

    if (syms)
    {
        for (int k = 0; k < (int)syms->cnt && k < virt_cnt; k++)
        {
            int idx = virt_idx[k];
            const struct blaze_sym *s = &syms->syms[k];
            if (s->name)
                strncpy(results[idx].name, s->name,
                        sizeof(results[idx].name) - 1);
            if (s->code_info.file)
            {
                strncpy(results[idx].src_path, s->code_info.file,
                        sizeof(results[idx].src_path) - 1);
                results[idx].src_line = s->code_info.line;
            }
            any = 1;
        }
        blaze_syms_free(syms);
    }

    blaze_symbolizer_free(sym);
    return any;
}

/* ========== 主入口 ========== */

int resolve_symbols(int pid, const char *comm, uint64_t load_base,
                    const uint64_t *addrs, size_t addr_cnt,
                    sym_info_t *results)
{
    if (!addrs || !results || addr_cnt == 0)
        return -1;

    memset(results, 0, addr_cnt * sizeof(sym_info_t));
    for (size_t i = 0; i < addr_cnt; i++)
        results[i].addr = addrs[i];

    if (load_base == 0)
    {
        load_modules_from_proc(pid);

        int bin_resolved = resolve_from_maps(addrs, addr_cnt, results);
        if (bin_resolved)
        {
            int all_done = 1;
            for (size_t i = 0; i < addr_cnt; i++)
            {
                if (results[i].name[0] == '\0')
                {
                    all_done = 0;
                    break;
                }
            }
            if (all_done)
                return (int)addr_cnt;
        }
    }

    resolve_from_binary(comm, load_base, addrs, addr_cnt, results);

    return (int)addr_cnt;
}

int resolve_kernel_symbols(const uint64_t *addrs, size_t addr_cnt,
                           sym_info_t *results)
{
    if (!addrs || !results || addr_cnt == 0)
        return -1;

    memset(results, 0, addr_cnt * sizeof(sym_info_t));
    for (size_t i = 0; i < addr_cnt; i++)
        results[i].addr = addrs[i];

    struct blaze_symbolizer_opts sym_opts = {
        .type_size = sizeof(sym_opts),
        .code_info = true,
        .inlined_fns = true,
    };
    blaze_symbolizer *sym = blaze_symbolizer_new_opts(&sym_opts);
    if (!sym)
        return (int)addr_cnt;

    struct blaze_symbolize_src_kernel src = {
        .type_size = sizeof(src),
    };

    const struct blaze_syms *syms =
        blaze_symbolize_kernel_abs_addrs(sym, &src, addrs, addr_cnt);

    if (syms)
    {
        for (size_t i = 0; i < syms->cnt && i < addr_cnt; i++)
        {
            const struct blaze_sym *s = &syms->syms[i];
            if (s->name)
                strncpy(results[i].name, s->name,
                        sizeof(results[i].name) - 1);
            if (s->module)
                strncpy(results[i].module, s->module,
                        sizeof(results[i].module) - 1);
            if (s->code_info.file)
            {
                strncpy(results[i].src_path, s->code_info.file,
                        sizeof(results[i].src_path) - 1);
                results[i].src_line = s->code_info.line;
            }
        }
        blaze_syms_free(syms);
    }

    blaze_symbolizer_free(sym);
    return (int)addr_cnt;
}