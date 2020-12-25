/*-------------------------------------------------------------------------
 *
 * compress_io.c
 *	 Routines for archivers to write an uncompressed or compressed data
 *	 stream.
 *
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * This file includes two APIs for dealing with compressed data. The first
 * provides more flexibility, using callbacks to read/write data from the
 * underlying stream. The second API is a wrapper around fopen/gzopen and
 * friends, providing an interface similar to those, but abstracts away
 * the possible compression. Both APIs use libz for the compression, but
 * the second API uses gzip headers, so the resulting files can be easily
 * manipulated with the gzip utility.
 *
 * Compressor API
 * --------------
 *
 *	The interface for writing to an archive consists of three functions:
 *	AllocateCompressor, WriteDataToArchive and EndCompressor. First you call
 *	AllocateCompressor, then write all the data by calling WriteDataToArchive
 *	as many times as needed, and finally EndCompressor. WriteDataToArchive
 *	and EndCompressor will call the WriteFunc that was provided to
 *	AllocateCompressor for each chunk of compressed data.
 *
 *	The interface for reading an archive consists of just one function:
 *	ReadDataFromArchive. ReadDataFromArchive reads the whole compressed input
 *	stream, by repeatedly calling the given ReadFunc. ReadFunc returns the
 *	compressed data one chunk at a time, and ReadDataFromArchive decompresses it
 *	and passes the decompressed data to ahwrite(), until ReadFunc returns 0
 *	to signal EOF.
 *
 *	The interface is the same for compressed and uncompressed streams.
 *
 * Compressed stream API
 * ----------------------
 *
 *	The compressed stream API is a wrapper around the C standard fopen() and
 *	libz's gzopen() APIs. It allows you to use the same functions for
 *	compressed and uncompressed streams. cfopen_read() first tries to open
 *	the file with given name, and if it fails, it tries to open the same
 *	file with the .gz suffix. cfopen_write() opens a file for writing, an
 *	extra argument specifies if the file should be compressed, and adds the
 *	.gz suffix to the filename if so. This allows you to easily handle both
 *	compressed and uncompressed files.
 *
 * IDENTIFICATION
 *	   src/bin/pg_dump/compress_io.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include "compress_io.h"
#include "pg_backup_utils.h"

const struct compressLibs
compresslibs[] = {
	{ COMPR_ALG_NONE, "no", "", 0, },
	{ COMPR_ALG_NONE, "none", "", 0, }, /* Alternate name */

// #ifdef HAVE_LIBZ?
	{ COMPR_ALG_LIBZ, "libz", ".gz", Z_DEFAULT_COMPRESSION },
	{ COMPR_ALG_LIBZ, "zlib", ".gz", Z_DEFAULT_COMPRESSION }, /* Alternate name */

	{ 0, NULL, } /* sentinel */
};

/*----------------------
 * Compressor API
 *----------------------
 */

/* typedef appears in compress_io.h */
struct CompressorState
{
	CompressionAlgorithm comprAlg;
	WriteFunc	writeF;

#ifdef HAVE_LIBZ
	z_streamp	zp;
	char	   *zlibOut;
	size_t		zlibOutSize;
#endif
};

/* Routines that support zlib compressed data I/O */
#ifdef HAVE_LIBZ
static void InitCompressorZlib(CompressorState *cs, Compress *compress);
static void DeflateCompressorZlib(ArchiveHandle *AH, CompressorState *cs,
								  bool flush);
static void ReadDataFromArchiveZlib(ArchiveHandle *AH, ReadFunc readF);
static void WriteDataToArchiveZlib(ArchiveHandle *AH, CompressorState *cs,
								   const char *data, size_t dLen);
static void EndCompressorZlib(ArchiveHandle *AH, CompressorState *cs);
#endif

/* Routines that support uncompressed data I/O */
static void ReadDataFromArchiveNone(ArchiveHandle *AH, ReadFunc readF);
static void WriteDataToArchiveNone(ArchiveHandle *AH, CompressorState *cs,
								   const char *data, size_t dLen);

/* Public interface routines */

/* Allocate a new compressor */
CompressorState *
AllocateCompressor(Compress *compression, WriteFunc writeF)
{
	CompressorState *cs;

	cs = (CompressorState *) pg_malloc0(sizeof(CompressorState));
	cs->writeF = writeF;
	cs->comprAlg = compression->alg;

	/*
	 * Perform compression algorithm specific initialization.
	 */
	Assert (compression->alg != COMPR_ALG_DEFAULT);
	switch (compression->alg)
	{
#ifdef HAVE_LIBZ
	case COMPR_ALG_LIBZ:
		InitCompressorZlib(cs, compression);
		break;
#endif
	case COMPR_ALG_NONE:
		/* Do nothing */
		break;
	default:
		/* Should not happen */
		fatal("requested compression not available in this installation");
	}

	return cs;
}

/*
 * Read all compressed data from the input stream (via readF) and print it
 * out with ahwrite().
 */
void
ReadDataFromArchive(ArchiveHandle *AH, ReadFunc readF)
{
	switch (AH->compression.alg)
	{
	case COMPR_ALG_NONE:
		ReadDataFromArchiveNone(AH, readF);
		break;
#ifdef HAVE_LIBZ
	case COMPR_ALG_LIBZ:
		ReadDataFromArchiveZlib(AH, readF);
		break;
#endif
	default:
		/* Should not happen */
		fatal("requested compression not available in this installation");
	}
}

/*
 * Compress and write data to the output stream (via writeF).
 */
void
WriteDataToArchive(ArchiveHandle *AH, CompressorState *cs,
				   const void *data, size_t dLen)
{
	switch (cs->comprAlg)
	{
#ifdef HAVE_LIBZ
		case COMPR_ALG_LIBZ:
			WriteDataToArchiveZlib(AH, cs, data, dLen);
			break;
#endif
		case COMPR_ALG_NONE:
			WriteDataToArchiveNone(AH, cs, data, dLen);
			break;

		default:
			/* Should not happen */
			fatal("requested compression not available in this installation");
	}
}

/*
 * Terminate compression library context and flush its buffers.
 */
void
EndCompressor(ArchiveHandle *AH, CompressorState *cs)
{
#ifdef HAVE_LIBZ
	if (cs->comprAlg == COMPR_ALG_LIBZ)
		EndCompressorZlib(AH, cs);
#endif
	free(cs);
}

/* Private routines, specific to each compression method. */

#ifdef HAVE_LIBZ
/*
 * Functions for zlib compressed output.
 */

static void
InitCompressorZlib(CompressorState *cs, Compress *compress)
{
	z_streamp	zp;

	zp = cs->zp = (z_streamp) pg_malloc(sizeof(z_stream));
	zp->zalloc = Z_NULL;
	zp->zfree = Z_NULL;
	zp->opaque = Z_NULL;

	/*
	 * zlibOutSize is the buffer size we tell zlib it can output to.  We
	 * actually allocate one extra byte because some routines want to append a
	 * trailing zero byte to the zlib output.
	 */
	cs->zlibOut = (char *) pg_malloc(ZLIB_OUT_SIZE + 1);
	cs->zlibOutSize = ZLIB_OUT_SIZE;

	if (deflateInit(zp, compress->level) != Z_OK)
		fatal("could not initialize compression library: %s",
			  zp->msg);

	/* Just be paranoid - maybe End is called after Start, with no Write */
	zp->next_out = (void *) cs->zlibOut;
	zp->avail_out = cs->zlibOutSize;
}

static void
EndCompressorZlib(ArchiveHandle *AH, CompressorState *cs)
{
	z_streamp	zp = cs->zp;

	zp->next_in = NULL;
	zp->avail_in = 0;

	/* Flush any remaining data from zlib buffer */
	DeflateCompressorZlib(AH, cs, true);

	if (deflateEnd(zp) != Z_OK)
		fatal("could not close compression stream: %s", zp->msg);

	free(cs->zlibOut);
	free(cs->zp);
}

static void
DeflateCompressorZlib(ArchiveHandle *AH, CompressorState *cs, bool flush)
{
	z_streamp	zp = cs->zp;
	char	   *out = cs->zlibOut;
	int			res = Z_OK;

	while (cs->zp->avail_in != 0 || flush)
	{
		res = deflate(zp, flush ? Z_FINISH : Z_NO_FLUSH);
		if (res == Z_STREAM_ERROR)
			fatal("could not compress data: %s", zp->msg);
		if ((flush && (zp->avail_out < cs->zlibOutSize))
			|| (zp->avail_out == 0)
			|| (zp->avail_in != 0)
			)
		{
			/*
			 * Extra paranoia: avoid zero-length chunks, since a zero length
			 * chunk is the EOF marker in the custom format. This should never
			 * happen but...
			 */
			if (zp->avail_out < cs->zlibOutSize)
			{
				/*
				 * Any write function should do its own error checking but to
				 * make sure we do a check here as well...
				 */
				size_t		len = cs->zlibOutSize - zp->avail_out;

				cs->writeF(AH, out, len);
			}
			zp->next_out = (void *) out;
			zp->avail_out = cs->zlibOutSize;
		}

		if (res == Z_STREAM_END)
			break;
	}
}

static void
WriteDataToArchiveZlib(ArchiveHandle *AH, CompressorState *cs,
					   const char *data, size_t dLen)
{
	cs->zp->next_in = (void *) unconstify(char *, data);
	cs->zp->avail_in = dLen;
	DeflateCompressorZlib(AH, cs, false);
}

static void
ReadDataFromArchiveZlib(ArchiveHandle *AH, ReadFunc readF)
{
	z_streamp	zp;
	char	   *out;
	int			res = Z_OK;
	size_t		cnt;
	char	   *buf;
	size_t		buflen;

	zp = (z_streamp) pg_malloc(sizeof(z_stream));
	zp->zalloc = Z_NULL;
	zp->zfree = Z_NULL;
	zp->opaque = Z_NULL;

	buf = pg_malloc(ZLIB_IN_SIZE);
	buflen = ZLIB_IN_SIZE;

	out = pg_malloc(ZLIB_OUT_SIZE + 1);

	if (inflateInit(zp) != Z_OK)
		fatal("could not initialize compression library: %s",
			  zp->msg);

	/* no minimal chunk size for zlib */
	while ((cnt = readF(AH, &buf, &buflen)))
	{
		zp->next_in = (void *) buf;
		zp->avail_in = cnt;

		while (zp->avail_in > 0)
		{
			zp->next_out = (void *) out;
			zp->avail_out = ZLIB_OUT_SIZE;

			res = inflate(zp, 0);
			if (res != Z_OK && res != Z_STREAM_END)
				fatal("could not uncompress data: %s", zp->msg);

			out[ZLIB_OUT_SIZE - zp->avail_out] = '\0';
			ahwrite(out, 1, ZLIB_OUT_SIZE - zp->avail_out, AH);
		}
	}

	zp->next_in = NULL;
	zp->avail_in = 0;
	while (res != Z_STREAM_END)
	{
		zp->next_out = (void *) out;
		zp->avail_out = ZLIB_OUT_SIZE;
		res = inflate(zp, 0);
		if (res != Z_OK && res != Z_STREAM_END)
			fatal("could not uncompress data: %s", zp->msg);

		out[ZLIB_OUT_SIZE - zp->avail_out] = '\0';
		ahwrite(out, 1, ZLIB_OUT_SIZE - zp->avail_out, AH);
	}

	if (inflateEnd(zp) != Z_OK)
		fatal("could not close compression library: %s", zp->msg);

	free(buf);
	free(out);
	free(zp);
}
#endif							/* HAVE_LIBZ */


/*
 * Functions for uncompressed output.
 */

static void
ReadDataFromArchiveNone(ArchiveHandle *AH, ReadFunc readF)
{
	size_t		cnt;
	char	   *buf;
	size_t		buflen;

	buf = pg_malloc(ZLIB_OUT_SIZE);
	buflen = ZLIB_OUT_SIZE;

	while ((cnt = readF(AH, &buf, &buflen)))
	{
		ahwrite(buf, 1, cnt, AH);
	}

	free(buf);
}

static void
WriteDataToArchiveNone(ArchiveHandle *AH, CompressorState *cs,
					   const char *data, size_t dLen)
{
	cs->writeF(AH, data, dLen);
}


/*----------------------
 * Compressed stream API
 *----------------------
 */

/*
 * cfp represents an open stream, wrapping the underlying FILE or gzFile
 * pointer. This is opaque to the callers.
 */
struct cfp
{
	FILE	   *uncompressedfp;
#ifdef HAVE_LIBZ
	gzFile		compressedfp;
#endif
};

static int	hasSuffix(const char *filename);

/* free() without changing errno; useful in several places below */
static void
free_keep_errno(void *p)
{
	int			save_errno = errno;

	free(p);
	errno = save_errno;
}

/*
 * Open a file for reading. 'path' is the file to open, and 'mode' should
 * be either "r" or "rb".
 *
 * If the file at 'path' does not exist, we search with compressed suffix (if 'path'
 * doesn't already have one) and try again. So if you pass "foo" as 'path',
 * this will open either "foo" or "foo.gz".
 *
 * On failure, return NULL with an error code in errno.
 */
cfp *
cfopen_read(const char *path, const char *mode, Compress *compression)
{
	cfp		   *fp;

	if (hasSuffix(path))
		fp = cfopen(path, mode, compression);
	else
	{
		fp = cfopen(path, mode, compression);
		if (fp == NULL)
		{
			char	   *fname;
			const char *suffix = compress_suffix(compression);

			fname = psprintf("%s%s", path, suffix);
			fp = cfopen(fname, mode, compression);
			free_keep_errno(fname);
		}
	}
	return fp;
}

/*
 * Open a file for writing. 'path' indicates the path name, and 'mode' must
 * be a filemode as accepted by fopen() and gzopen() that indicates writing
 * ("w", "wb", "a", or "ab").
 *
 * Use compression if specified.
 * The appropriate suffix is automatically added to 'path' in that case.
 *
 * On failure, return NULL with an error code in errno.
 */
cfp *
cfopen_write(const char *path, const char *mode, Compress *compression)
{
	cfp		   *fp;

	if (compression->alg == COMPR_ALG_NONE)
		fp = cfopen(path, mode, compression);
	else
	{
		char	   *fname;
		const char *suffix = compress_suffix(compression);

		fname = psprintf("%s%s", path, suffix);
		fp = cfopen(fname, mode, compression);
		free_keep_errno(fname);
	}
	return fp;
}

/*
 * Opens file 'path' in 'mode'. If 'compression' is non-zero, the file
 * is opened with libz gzopen(), otherwise with plain fopen().
 *
 * On failure, return NULL with an error code in errno.
 */
cfp *
cfopen(const char *path, const char *mode, Compress *compression)
{
	cfp		   *fp = pg_malloc0(sizeof(cfp));

	switch (compression->alg)
	{
#ifdef HAVE_LIBZ
	case COMPR_ALG_LIBZ:
		if (compression->level != Z_DEFAULT_COMPRESSION)
		{
			/* user has specified a compression level, so tell zlib to use it */
			char		mode_compression[32];

			snprintf(mode_compression, sizeof(mode_compression), "%s%d",
					 mode, compression->level);
			fp->compressedfp = gzopen(path, mode_compression);
		}
		else
		{
			/* don't specify a level, just use the zlib default */
			fp->compressedfp = gzopen(path, mode);
		}

		if (fp->compressedfp == NULL)
		{
			free_keep_errno(fp);
			fp = NULL;
		}
		return fp;
#endif

	case COMPR_ALG_NONE:
		fp->uncompressedfp = fopen(path, mode);
		if (fp->uncompressedfp == NULL)
		{
			free_keep_errno(fp);
			fp = NULL;
		}
		return fp;

	default:
		/* Should not happen */
		fatal("requested compression not available in this installation");
	}
}


int
cfread(void *ptr, int size, cfp *fp)
{
	int			ret;

	if (size == 0)
		return 0;

#ifdef HAVE_LIBZ
	if (fp->compressedfp)
	{
		ret = gzread(fp->compressedfp, ptr, size);
		if (ret != size && !gzeof(fp->compressedfp))
		{
			int			errnum;
			const char *errmsg = gzerror(fp->compressedfp, &errnum);

			fatal("could not read from input file: %s",
				  errnum == Z_ERRNO ? strerror(errno) : errmsg);
		}
		return ret;
	}
#endif

	ret = fread(ptr, 1, size, fp->uncompressedfp);
	if (ret != size && !feof(fp->uncompressedfp))
		READ_ERROR_EXIT(fp->uncompressedfp);
	return ret;
}

int
cfwrite(const void *ptr, int size, cfp *fp)
{
#ifdef HAVE_LIBZ
	if (fp->compressedfp)
		return gzwrite(fp->compressedfp, ptr, size);
#endif
	return fwrite(ptr, 1, size, fp->uncompressedfp);
}

int
cfgetc(cfp *fp)
{
	int			ret;

#ifdef HAVE_LIBZ
	if (fp->compressedfp)
	{
		ret = gzgetc(fp->compressedfp);
		if (ret == EOF)
		{
			if (!gzeof(fp->compressedfp))
				fatal("could not read from input file: %s", strerror(errno));
			else
				fatal("could not read from input file: end of file");
		}
		return ret;
	}
#endif
	ret = fgetc(fp->uncompressedfp);
	if (ret == EOF)
		READ_ERROR_EXIT(fp->uncompressedfp);
	return ret;
}

char *
cfgets(cfp *fp, char *buf, int len)
{
#ifdef HAVE_LIBZ
	if (fp->compressedfp)
		return gzgets(fp->compressedfp, buf, len);
#endif
	return fgets(buf, len, fp->uncompressedfp);
}

int
cfclose(cfp *fp)
{
	int			result;

	if (fp == NULL)
	{
		errno = EBADF;
		return EOF;
	}
#ifdef HAVE_LIBZ
	if (fp->compressedfp)
	{
		result = gzclose(fp->compressedfp);
		fp->compressedfp = NULL;
		return result;
	}
#endif

	result = fclose(fp->uncompressedfp);
	fp->uncompressedfp = NULL;
	free_keep_errno(fp);
	return result;
}

int
cfeof(cfp *fp)
{
#ifdef HAVE_LIBZ
	if (fp->compressedfp)
		return gzeof(fp->compressedfp);
#endif

	return feof(fp->uncompressedfp);
}

const char *
get_cfp_error(cfp *fp)
{
#ifdef HAVE_LIBZ
	if (fp->compressedfp)
	{
		int			errnum;
		const char *errmsg = gzerror(fp->compressedfp, &errnum);

		if (errnum != Z_ERRNO)
			return errmsg;
	}
#endif
	return strerror(errno);
}

/* Return true iff the filename has a known compression suffix */
static int
hasSuffix(const char *filename)
{
	for (int i = 0; compresslibs[i].name != NULL; ++i)
	{
		const char	*suffix = compresslibs[i].suffix;
		int			filenamelen = strlen(filename);
		int			suffixlen = strlen(suffix);

		/* COMPR_ALG_NONE has an empty "suffix", which doesn't count */
		if (suffixlen == 0)
			continue;

		if (filenamelen < suffixlen)
			continue;

		if (memcmp(&filename[filenamelen - suffixlen],
					  suffix, suffixlen) == 0)
			return true;
	}

	return false;
}

/*
 * Return a string for the given AH's compression.
 * The string is statically allocated.
 */
const char *
compress_suffix(Compress *compression)
{
	for (int i = 0; compresslibs[i].name != NULL; ++i)
	{
		if (compression->alg != compresslibs[i].alg)
			continue;

		return compresslibs[i].suffix;
	}

	return "";
}
