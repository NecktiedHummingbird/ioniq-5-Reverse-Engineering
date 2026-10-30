/* Diagnostic scaffolding for the ias-backend-soft crash hunt. Not shipped. */
#ifndef IAS_DBG_H
#define IAS_DBG_H
void ias_dbg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int ias_dbg_fd(void);
void ias_dbg_trap(void);
#endif
