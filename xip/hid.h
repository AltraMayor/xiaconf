#ifndef HEADER_HID_H
#define HEADER_HID_H

#include <stdio.h>

/* get_ffn - obtains Final FileName.
 *
 * @ffn must be at least PATH_MAX (available in <limits.h>).
 *
 * If @filename includes a '/', it assumes to be a filename with full path,
 * otherwise it assumes it is to be stored in the default configuration path.
 */
void get_ffn(char *ffn, const char *filename);

/* write_new_hid_file - generates a new HID and save to @filename.
 *
 * RETURN
 *	returns zero on success; otherwise a negative number.
 */
int write_new_hid_file(const char *filename);

/* write_pub_hid_file - reads @infilename, a file with the private key, and
 * writes @outf a file with the public key.
 *
 * RETURN
 *	returns zero on success; otherwise a negative number.
 */
int write_pub_hid_file(const char *infilename, FILE *outf);

#endif /* HEADER_HID_H */
