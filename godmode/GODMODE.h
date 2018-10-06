#pragma once

#ifdef LIBRARY_IMPL
#define PRX_INTERFACE __declspec(dllexport)
#else
#define PRX_INTERFACE __declspec(dllimport)
#endif

#ifndef __cplusplus
extern "C++" {
#endif
PRX_INTERFACE int debug(const char *format, ...);
#ifndef __cplusplus
}
#endif