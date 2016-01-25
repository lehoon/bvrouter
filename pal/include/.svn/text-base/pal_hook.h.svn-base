#ifndef _HOOK_H_
#define _HOOK_H_

/*
 * @brief Set the directory where hook libs should be found
 * @param dir Path of the directory. Can be absolute path or relative path
 * @return 0 on success, -1 on failure
 * @note  1. PAL does not have a default location for hooklibs.
 *        2. PAL doesn't check the validity of the path.
 */
extern int pal_hook_set_libdir(const char *dir);

/*
 * @brief Load a dynamic linked library at runtime.
 * @param name Name of the lib. Must be unique in the program.
 *        Like gcc, the full name searched by PAL is actually "libname.so". 
 * @return 0 on success, -1 on failure
 * @note  Make sure you set the hook lib directory before load the lib
 */
extern int pal_hook_load(const char *name);

/*
 * @brief Unload a dynamic loaded library
 * @param name Name of the library to be unloaded
 * @return 0 on success, -1 on failure
 */
extern int pal_hook_unload(const char *name);


/* TODO: implement a method to export statistics data of hook libs */

#endif
