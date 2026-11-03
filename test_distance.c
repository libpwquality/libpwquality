/*
 * 独立测试 distance() Wagner-Fischer 滚动数组实现
 * 从 src/check.c commit 30d0d098 提取
 *
 * 编译: gcc -o test_distance -Wall -Wextra -std=c99 test_distance.c
 * 运行: ./test_distance
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

#define MIN(_a, _b) (((_a) < (_b)) ? (_a) : (_b))

static int
distance(const char *old, const char *new)
{
        const char *s, *t;          /* s: 较长串, t: 较短串 */
        int *prev = NULL;           /* 上一行 D[i-1][*] */
        int *curr = NULL;           /* 当前行 D[i][*]   */
        int *swaprow;
        size_t m, n, i, j, tmp;
        int r = -1;
        int cost, del, ins, sub;

        m = strlen(old);
        n = strlen(new);

        /*
         * 让 s 指向较长串、t 指向较短串。
         * 滚动数组按 t 的长度 n 分配，因此取 n = min(m,n)。
         * Levenshtein 距离对称，交换不影响结果。
         */
        if (m < n) {
                s = new;
                t = old;
                tmp = m;
                m = n;
                n = tmp;
        } else {
                s = old;
                t = new;
        }

        /*
         * 距离上界为 max(m,n) = m。
         * 递推中会出现 prev[j] + 1，最大为 m + 1，
         * 必须保证 m + 1 <= INT_MAX，否则 int 溢出。
         * 同时 curr[0] = (int)i 需要 i <= INT_MAX。
         *
         * 因此要求 m <= INT_MAX - 1。
         * 实际密码场景不可达（2GB 字符串），但保持严格。
         */
        if (m > (size_t)(INT_MAX - 1))
                return -1;

        prev = malloc((n + 1) * sizeof(int));
        curr = malloc((n + 1) * sizeof(int));
        if (prev == NULL || curr == NULL)
                goto out;           /* r 保持 -1，free(NULL) 安全 */

        /*
         * 边界：D[0][j] = j。
         * prev 行初始对应 i = 0（s 的空前缀）。
         * 此时 prev[j] = 把空串变成 t[0..j-1] 的插入次数 = j。
         */
        for (j = 0; j <= n; j++)
                prev[j] = (int)j;

        /*
         * 主循环：逐行计算 D[i][*]。
         * 每轮结束交换 prev/curr，使 prev 指向刚算完的行，
         * curr 指向旧行（下一轮会被 curr[0] 和 curr[j] 完全覆盖）。
         */
        for (i = 1; i <= m; i++) {
                /*
                 * 边界：D[i][0] = i。
                 * 即 s[0..i-1] 变成空串，只能删除 i 次。
                 */
                curr[0] = (int)i;

                for (j = 1; j <= n; j++) {
                        /*
                         * cost = 0 表示 s[i-1] == t[j-1]，无需替换；
                         * cost = 1 表示需要一次替换。
                         */
                        cost = (s[i - 1] != t[j - 1]);

                        /*
                         * 三个来源：
                         *   del = D[i-1][j]   + 1  → 删除 s[i-1]（上方）
                         *   ins = D[i][j-1]   + 1  → 插入 t[j-1]（左方，本轮已算）
                         *   sub = D[i-1][j-1] + cost → 替换/匹配（左上）
                         *
                         * 注意 prev 是上一行，curr 是本行：
                         *   prev[j]   = D[i-1][j]
                         *   curr[j-1] = D[i][j-1]
                         *   prev[j-1] = D[i-1][j-1]
                         */
                        del = prev[j] + 1;
                        ins = curr[j - 1] + 1;
                        sub = prev[j - 1] + cost;

                        /* D[i][j] = min(del, ins, sub) */
                        curr[j] = MIN(MIN(del, ins), sub);
                }

                /* 滚动：prev <- curr，curr <- 旧 prev（下一轮复用） */
                swaprow = prev;
                prev = curr;
                curr = swaprow;
        }

        /*
         * 循环结束后 prev 指向第 m 行，即 D[m][*]。
         * D[m][n] 就是完整编辑距离。
         * 若 m == 0（两串均为空或 n == 0），prev 仍是初始 row 0，
         * prev[n] = n，恰好等于正确距离。
         */
        r = prev[n];

out:
        free(prev);
        free(curr);
        return r;
}

/* ================================================================
 * 参考实现：标准 O(n²) 全矩阵 DP（用于交叉验证）
 * 虽然慢，但逻辑简单不易错。
 * ================================================================ */
static int
distance_ref(const char *s1, const char *s2)
{
        size_t m = strlen(s1), n = strlen(s2);
        int **d;
        size_t i, j;
        int cost, result;

        d = malloc((m + 1) * sizeof(int *));
        for (i = 0; i <= m; i++)
                d[i] = calloc(n + 1, sizeof(int));

        for (i = 0; i <= m; i++)
                d[i][0] = (int)i;
        for (j = 0; j <= n; j++)
                d[0][j] = (int)j;

        for (i = 1; i <= m; i++) {
                for (j = 1; j <= n; j++) {
                        cost = (s1[i - 1] != s2[j - 1]);
                        d[i][j] = MIN(MIN(d[i - 1][j] + 1,
                                          d[i][j - 1] + 1),
                                      d[i - 1][j - 1] + cost);
                }
        }

        result = d[m][n];
        for (i = 0; i <= m; i++)
                free(d[i]);
        free(d);
        return result;
}

/* ================================================================
 * 测试用例
 * ================================================================ */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  %-50s", name); } while (0)
#define PASS()  do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)
#define ASSERT_INT_EQ(a, b) do { \
        int _a = (a), _b = (b); \
        if (_a != _b) { \
                char _buf[128]; \
                snprintf(_buf, sizeof(_buf), "expected %d, got %d", _b, _a); \
                FAIL(_buf); \
                return; \
        } \
} while (0)

#define ASSERT_GE(a, b) do { \
        int _a = (a), _b = (b); \
        if (_a < _b) { \
                char _buf[128]; \
                snprintf(_buf, sizeof(_buf), "expected >= %d, got %d", _b, _a); \
                FAIL(_buf); \
                return; \
        } \
} while (0)

static void test_both_empty(void)
{
        TEST("both empty strings");
        ASSERT_INT_EQ(distance("", ""), 0);
        PASS();
}

static void test_one_empty(void)
{
        TEST("old empty, new 'abc'");
        ASSERT_INT_EQ(distance("", "abc"), 3);
        PASS();
}

static void test_other_empty(void)
{
        TEST("old 'abc', new empty");
        ASSERT_INT_EQ(distance("abc", ""), 3);
        PASS();
}

static void test_identical(void)
{
        TEST("identical 'kitten'");
        ASSERT_INT_EQ(distance("kitten", "kitten"), 0);
        PASS();
}

static void test_classic_kitten_sitting(void)
{
        TEST("kitten -> sitting (classic=3)");
        ASSERT_INT_EQ(distance("kitten", "sitting"), 3);
        PASS();
}

static void test_single_char_replace(void)
{
        TEST("'a' -> 'b' (1 replace)");
        ASSERT_INT_EQ(distance("a", "b"), 1);
        PASS();
}

static void test_single_char_delete(void)
{
        TEST("'ab' -> 'a' (1 delete)");
        ASSERT_INT_EQ(distance("ab", "a"), 1);
        PASS();
}

static void test_single_char_insert(void)
{
        TEST("'a' -> 'ab' (1 insert)");
        ASSERT_INT_EQ(distance("a", "ab"), 1);
        PASS();
}

static void test_symmetry(void)
{
        TEST("symmetry: dist(a,b) == dist(b,a)");
        struct { const char *a; const char *b; int d; } cases[] = {
                {"abc", "def", 3},
                {"hello", "world", 4},
                {"password", "p@ssw0rd", 2},
                {"levenshtein", "levenstein", 1},
                {"12345678", "1234abcd", 4},
                {"qwerty", "qwerto", 1},
                {NULL, NULL, 0}
        };
        for (int k = 0; cases[k].a; k++) {
                ASSERT_INT_EQ(distance(cases[k].a, cases[k].b), cases[k].d);
                ASSERT_INT_EQ(distance(cases[k].b, cases[k].a), cases[k].d);
        }
        PASS();
}

static void test_substring_vs_full(void)
{
        TEST("substring relations");
        ASSERT_INT_EQ(distance("abc", "abcabc"), 3); /* insert abc at end */
        ASSERT_INT_EQ(distance("abc", "xabc"), 1);   /* insert x at front */
        PASS();
}

static void test_similarity(void)
{
        TEST("similarity (distance <= 2)");
        /* 子串 */
        ASSERT_INT_EQ(distance("123456", "123456789"), 3);
        /* 反转 */
        ASSERT_INT_EQ(distance("abcde", "edcba"), 4);
        /* 旋转 */
        ASSERT_INT_EQ(distance("password", "asswordp"), 2);
        PASS();
}

static void test_unicode_multibyte(void)
{
        TEST("UTF-8 multibyte characters");
        /* 中文字符对比 (每个中文字符3字节，距离按字节计算) */
        ASSERT_INT_EQ(distance("你好", "你好"), 0);
        ASSERT_INT_EQ(distance("你好", "您好"), 3); /* 你→您: 3 bytes differ */
        ASSERT_INT_EQ(distance("密码", "口令"), 5); /* e5af86e7a081→e58fa3e4bba4 */
        ASSERT_INT_EQ(distance("你好", "口令"), 6); /* 全部6字节不同 */
        /* 混合中英文 */
        ASSERT_INT_EQ(distance("hello世界", "hello中国"), 4); /* 96e7958c→ade59bbd */
        PASS();
}

static void test_long_string_no_overflow(void)
{
        TEST("long strings (10K chars, regression test)");
        const int N = 10000;
        char *a = malloc(N + 1);
        char *b = malloc(N + 1);
        assert(a && b);

        /* a: all 'x',  b: all 'x' except last char = 'y' → distance = 1 */
        memset(a, 'x', N);
        a[N] = '\0';
        memcpy(b, a, N + 1);
        b[N - 1] = 'y';

        int d = distance(a, b);
        ASSERT_INT_EQ(d, 1);

        free(a);
        free(b);
        PASS();
}

static void test_identical_long(void)
{
        TEST("identical 10K strings → distance 0");
        const int N = 10000;
        char *a = malloc(N + 1);
        assert(a);
        memset(a, 'A', N);
        a[N] = '\0';

        ASSERT_INT_EQ(distance(a, a), 0);
        free(a);
        PASS();
}

static void test_distance_bound(void)
{
        TEST("distance <= max(len(a), len(b))");
        struct { const char *a; const char *b; int maxlen; } cases[] = {
                {"abcd", "xyz", 4},
                {"short", "longerstring", 12},
                {"", "abc", 3},
                {"same", "same", 4},
                {NULL, NULL, 0}
        };
        for (int k = 0; cases[k].a; k++) {
                int d = distance(cases[k].a, cases[k].b);
                ASSERT_GE(cases[k].maxlen, d);
        }
        PASS();
}

static void test_triangle_inequality(void)
{
        TEST("triangle inequality: d(a,c) <= d(a,b) + d(b,c)");
        struct { const char *a; const char *b; const char *c; } cases[] = {
                {"kitten", "sitting", "bitten"},
                {"abc", "def", "ghi"},
                {"hello", "hallo", "hullo"},
                {NULL, NULL, NULL}
        };
        for (int k = 0; cases[k].a; k++) {
                int dab = distance(cases[k].a, cases[k].b);
                int dbc = distance(cases[k].b, cases[k].c);
                int dac = distance(cases[k].a, cases[k].c);
                ASSERT_GE(dab + dbc, dac);
        }
        PASS();
}

static void test_against_reference_small(void)
{
        TEST("cross-validate small cases against reference DP");
        const char *cases[] = {
                "", "a", "ab", "abc", "abcd",
                "kitten", "sitting", "password", "p@ssw0rd",
                "hello", "world", "你好", "您好",
                "12345678", "abcdefgh", NULL
        };
        for (int i = 0; cases[i]; i++) {
                for (int j = 0; cases[j]; j++) {
                        int d1 = distance(cases[i], cases[j]);
                        int d2 = distance_ref(cases[i], cases[j]);
                        if (d1 != d2) {
                                char buf[128];
                                snprintf(buf, sizeof(buf),
                                         "mismatch on (%s, %s): %d vs %d",
                                         cases[i], cases[j], d1, d2);
                                FAIL(buf);
                                return;
                        }
                }
        }
        PASS();
}

static void test_against_reference_medium(void)
{
        TEST("cross-validate random medium strings (len 100)");
        srand(42);
        char a[101], b[101];
        for (int trial = 0; trial < 20; trial++) {
                for (int i = 0; i < 100; i++) {
                        a[i] = (char)('a' + (rand() % 26));
                        b[i] = (char)('a' + (rand() % 26));
                }
                a[100] = b[100] = '\0';
                int d1 = distance(a, b);
                int d2 = distance_ref(a, b);
                if (d1 != d2) {
                        FAIL("random medium mismatch");
                        return;
                }
        }
        PASS();
}

static void test_abcd_all_substrings(void)
{
        TEST("all substring pairs of 'abcd' vs reference");
        const char *s = "abcd";
        size_t len = strlen(s);
        for (size_t i1 = 0; i1 <= len; i1++) {
                for (size_t j1 = i1; j1 <= len; j1++) {
                        char sub1[5];
                        memcpy(sub1, s + i1, j1 - i1);
                        sub1[j1 - i1] = '\0';
                        for (size_t i2 = 0; i2 <= len; i2++) {
                                for (size_t j2 = i2; j2 <= len; j2++) {
                                        char sub2[5];
                                        memcpy(sub2, s + i2, j2 - i2);
                                        sub2[j2 - i2] = '\0';
                                        int d1 = distance(sub1, sub2);
                                        int d2 = distance_ref(sub1, sub2);
                                        if (d1 != d2) {
                                                char buf[128];
                                                snprintf(buf, sizeof(buf),
                                                         "substring mismatch (%s,%s): %d vs %d",
                                                         sub1, sub2, d1, d2);
                                                FAIL(buf);
                                                return;
                                        }
                                }
                        }
                }
        }
        PASS();
}

static void test_same_length_systematic(void)
{
        TEST("systematic: all length=3 strings over 'ab'");
        const char alpha[] = "ab";
        int na = (int)strlen(alpha);
        for (int i0 = 0; i0 < na; i0++)
        for (int i1 = 0; i1 < na; i1++)
        for (int i2 = 0; i2 < na; i2++)
        for (int j0 = 0; j0 < na; j0++)
        for (int j1 = 0; j1 < na; j1++)
        for (int j2 = 0; j2 < na; j2++) {
                char a[] = {alpha[i0], alpha[i1], alpha[i2], '\0'};
                char b[] = {alpha[j0], alpha[j1], alpha[j2], '\0'};
                int d1 = distance(a, b);
                int d2 = distance_ref(a, b);
                if (d1 != d2) {
                        char buf[128];
                        snprintf(buf, sizeof(buf),
                                 "mismatch (%s,%s): %d vs %d", a, b, d1, d2);
                        FAIL(buf);
                        return;
                }
        }
        PASS();
}

static void test_mixed_length_systematic(void)
{
        TEST("systematic: all pairs up to length 4 over 'ab'");
        const char *all[] = {
                "", "a", "b", "aa", "ab", "ba", "bb",
                "aaa", "aab", "aba", "abb", "baa", "bab", "bba", "bbb",
                "aaaa", "aaab", "aaba", "aabb", "abaa", "abab", "abba", "abbb",
                "baaa", "baab", "baba", "babb", "bbaa", "bbab", "bbba", "bbbb",
                NULL
        };
        int n = 0;
        while (all[n]) n++;

        for (int i = 0; i < n; i++) {
                for (int j = 0; j < n; j++) {
                        int d1 = distance(all[i], all[j]);
                        int d2 = distance_ref(all[i], all[j]);
                        if (d1 != d2) {
                                char buf[128];
                                snprintf(buf, sizeof(buf),
                                         "mismatch (%s,%s): %d vs %d",
                                         all[i], all[j], d1, d2);
                                FAIL(buf);
                                return;
                        }
                }
        }
        PASS();
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
        printf("\n=== distance() Wagner-Fischer rolling array tests ===\n\n");

        /* 基本功能 */
        printf("Basic functionality:\n");
        test_both_empty();
        test_one_empty();
        test_other_empty();
        test_identical();
        test_classic_kitten_sitting();
        test_single_char_replace();
        test_single_char_delete();
        test_single_char_insert();
        printf("  (%d/%d passed)\n\n", tests_passed, tests_run);

        /* 数学性质 */
        printf("Mathematical properties:\n");
        test_symmetry();
        test_distance_bound();
        test_triangle_inequality();
        printf("  (%d/%d cumulative)\n\n", tests_passed, tests_run);

        /* 实际场景 */
        printf("Real-world scenarios:\n");
        test_similarity();
        test_substring_vs_full();
        test_unicode_multibyte();
        printf("  (%d/%d cumulative)\n\n", tests_passed, tests_run);

        /* 回归测试（原栈溢出漏洞） */
        printf("Regression (stack overflow):\n");
        test_long_string_no_overflow();
        test_identical_long();
        printf("  (%d/%d cumulative)\n\n", tests_passed, tests_run);

        /* 交叉验证 */
        printf("Cross-validation against reference DP:\n");
        test_against_reference_small();
        test_against_reference_medium();
        test_abcd_all_substrings();
        test_same_length_systematic();
        test_mixed_length_systematic();
        printf("  (%d/%d cumulative)\n\n", tests_passed, tests_run);

        /* 结果汇总 */
        printf("========================================\n");
        printf("TOTAL: %d/%d passed", tests_passed, tests_run);
        if (tests_passed == tests_run) {
                printf(" — ALL PASSED\n");
        } else {
                printf(" — %d FAILED\n", tests_run - tests_passed);
        }
        printf("========================================\n\n");

        return (tests_passed == tests_run) ? 0 : 1;
}