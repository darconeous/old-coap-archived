/* GNU mailutils - a suite of utilities for electronic mail
   Copyright (C) 1999, 2000, 2001 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Library Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* First implementation by Alain Magloire */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default value for line length.  */
static const int line_size = 128;

ssize_t
getdelim (char **lineptr, size_t *n, int delim, FILE *stream)
{
  int indx = 0;
  int c;

  /* Sanity checks.  */
  if (lineptr == NULL || n == NULL || stream == NULL)
    return -1;

  /* Allocate the line the first time.  */
  if (*lineptr == NULL)
    {
      *lineptr = malloc (line_size);
      if (*lineptr == NULL)
        return -1;
      *n = line_size;
    }

  /* Clear the line.  */
  memset (*lineptr, '\0', *n);

  while ((c = getc (stream)) != EOF)
    {
      /* Check if more memory is needed.  */
      if (indx >= *n)
        {
          *lineptr = realloc (*lineptr, *n + line_size);
          if (*lineptr == NULL)
            {
              return -1;
            }
          /* Clear the rest of the line.  */
          memset(*lineptr + *n, '\0', line_size);
          *n += line_size;
        }

      /* Push the result in the line.  */
      (*lineptr)[indx++] = c;

      /* Bail out.  */
      if (c == delim)
        {
          break;
        }
    }
  return (c == EOF) ? -1 : indx;
}

ssize_t
getline (char **lineptr, size_t *n, FILE *stream)
{
  return getdelim (lineptr, n, '\n', stream);
}

#ifdef STANDALONE
int main(void)
{
  FILE * fp;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;
  fp = fopen("/etc/passwd", "r");
  if (fp == NULL)
    exit(EXIT_FAILURE);
  while ((read = getline(&line, &len, fp)) != -1) {
    printf("Retrieved line of length %zu :\n", read);
    printf("%s", line);
  }
  if (line)
    free(line);
  return EXIT_SUCCESS;
}
#endif
