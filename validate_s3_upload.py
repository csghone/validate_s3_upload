#!/usr/bin/env python3
from __future__ import print_function

import os
import sys
import argparse
import traceback
import logging
import logging.handlers
import math
import hashlib

import boto3

logger = logging.getLogger()
LOG_FORMATTER = logging.Formatter(
    "%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - " +
    "%(lineno)s - %(funcName)s - " +
    "%(message)s",
    "%Y%m%d %H:%M:%S")

S3 = boto3.client("s3")


def setup_logging(level=logging.INFO, enable_console=True):
    file_log_handler = logging.handlers.RotatingFileHandler(
        "__" + os.path.basename(__file__) + ".main__" + ".log",
        maxBytes=1000000,
        backupCount=5)
    console_log_handler = logging.StreamHandler()
    logger.addHandler(file_log_handler)
    if enable_console:
        logger.addHandler(console_log_handler)
    logger.setLevel(level)
    for handler in logging.root.handlers:
        handler.setFormatter(fmt=LOG_FORMATTER)


def get_s3_object(inp_s3_path, local_basename=None):
    s3_path = inp_s3_path
    s3_path = s3_path.replace(r"s3://", "")

    remote_basename = os.path.basename(s3_path)
    if remote_basename == "" and local_basename is not None:
        s3_path = os.path.join(s3_path, local_basename)

    bucket = s3_path.split("/")[0]
    s3_key = "/".join(s3_path.split("/")[1:])

    logger.debug("Attempting to get")
    logger.debug("Bucket: %s", bucket)
    logger.debug("Key: %s", s3_key)

    try:
        s3_obj = S3.get_object(Bucket=bucket, Key=s3_key)
    except:
        s3_obj = None

    if s3_obj is None:
        if s3_path[-1] == "/":
            logger.error("Cannot find object: %s", s3_path)
            return None
        if local_basename is not None:
            logger.warning("Trying by adding / at the end")
            return get_s3_object(s3_path + "/" + local_basename)

    return s3_obj


def get_chunk_size(local_file, chunks):
    filesize = os.stat(local_file).st_size
    logger.debug("local filesize for: %s: %s", local_file, filesize)
    chunk_size = int(math.ceil(filesize / chunks / 1024.0 / 1024.0))
    logger.info("chunk_size for: %s: %s MB", local_file, chunk_size)
    return chunk_size * 1024 * 1024


def calculate_local_etag(local_file, chunk_size):
    # Ref: https://github.com/tlastowka/calculate_multipart_etag/blob/master/calculate_multipart_etag.py
    md5s = []

    file_handle = open(local_file, mode="rb")
    while True:
        data = file_handle.read(chunk_size)
        if not data:
            break
        chunk_digest = hashlib.md5(data)
        logger.debug("Chunk digest: %s", chunk_digest.hexdigest())
        md5s.append(chunk_digest)
    file_handle.close()

    if len(md5s) == 1:
        final_etag = "{}".format(md5s[0].hexdigest())
    else:
        digests = b"".join(item.digest() for item in md5s)
        final_md5 = hashlib.md5(digests)
        final_etag = "{}-{}".format(final_md5.hexdigest(), len(md5s))

    if final_etag.endswith("-0"):
        final_etag = final_etag.strip("-0")

    logger.debug("Intermediate etag for: %s: %s", local_file, final_etag)
    return final_etag


def get_chunks(etag):
    if "-" in etag:
        try:
            chunks = int(etag.split("-")[1])
        except ValueError:
            logger.error("Unexpected ETag: %s", etag)
            assert False
    else:
        chunks = 1
    return chunks


def get_local_etag(local_file, s3_etag, inp_chunk_size=None):
    chunks = get_chunks(s3_etag)

    chunk_size = get_chunk_size(local_file, chunks)
    if inp_chunk_size is not None:
        chunk_size = kwargs["chunk_size"] * 1024 * 1024

    while True:
        local_etag = calculate_local_etag(local_file, chunk_size)
        if get_chunks(local_etag) != chunks:
            break
        if local_etag == s3_etag:
            break
        chunk_size += 1024 * 1024
        logger.info("Trying chunk_size: %s MB", chunk_size / 1024 / 1024)

    logger.info("Local ETag: %s: %s", local_file, local_etag)
    return local_etag


def get_s3_etag(s3_obj):
    s3_etag = s3_obj["ETag"].strip('"')
    logger.info("S3 Etag: %s", s3_etag)
    return s3_etag


def get_s3_size(s3_obj):
    s3_size = int(s3_obj["ContentLength"])
    return s3_size


def compare_files(local_file, s3_path, inp_chunk_size=None):
    if not os.path.exists(local_file):
        logger.error("Path does not exist")
        return False
    if not os.path.isfile(local_file):
        logger.error("Directories/links are not supported")
        return False

    assert s3_path.startswith(r"s3://"), logger.error("Invalid s3_path: %s", s3_path)
    s3_path = s3_path.replace(r"s3://", "")

    local_basename = os.path.basename(local_file)
    s3_obj = get_s3_object(s3_path, local_basename)
    if s3_obj is None:
        return False

    s3_etag = get_s3_etag(s3_obj)
    s3_size = get_s3_size(s3_obj)

    local_size = os.stat(local_file).st_size
    if s3_size != local_size:
        logger.error("Mismatch in size: s3: %s, local: %s", s3_size, local_size)
        return False

    local_etag = get_local_etag(local_file, s3_etag, inp_chunk_size)

    if local_etag != s3_etag:
        logger.error("Local file does not match Remote")
        return False

    return True


def process(**kwargs):
    local_file = kwargs["local_file"]
    s3_path = kwargs["s3_path"]
    if not compare_files(local_file, s3_path, inp_chunk_size=kwargs["chunk_size"]):
        return -1

    logger.info("Local file matches Remote")
    if kwargs["delete_local"]:
        logger.info("Deleting local file")
        os.remove(local_file)

    return 0


def main():
    parser = argparse.ArgumentParser(description="Validate S3 uploads")
    parser.add_argument(
        "-l",
        "--local_file",
        dest="local_file",
        help="Path to file on local disk",
        required=True
    )
    parser.add_argument(
        "-s",
        "--s3_path",
        dest="s3_path",
        help="s3://bucket/dir1/dir2/file or s3://dir1/dir2/",
        required=True
    )
    parser.add_argument(
        "-d",
        "--delete_local",
        dest="delete_local",
        action="store_true",
        help="Delete local file if checksum matches",
        default=False
    )
    parser.add_argument(
        "-c",
        "--chunk_size",
        dest="chunk_size",
        type=int,
        help="Override chunk_size",
        default=None
    )
    myargs = parser.parse_args()

    return process(**vars(myargs))


if __name__ == '__main__':
    setup_logging(level=logging.INFO)
    try:
        sys.exit(main()) # Ensure return value is passed to shell
    except Exception as error: # pylint: disable=W0702, W0703
        exc_mesg = traceback.format_exc()
        logger.error("\n%s", exc_mesg)
        logger.error("Error: %s", error)
        sys.exit(-1)
