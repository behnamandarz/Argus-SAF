import hashlib
import io
import os
import time

import pkg_resources
from concurrent import futures

from nativedroid.analyses.nativedroid_analysis import *
from nativedroid.jawa.utils import *
from nativedroid.protobuf.server_pb2 import *
from nativedroid.protobuf.server_pb2_grpc import *

__author__ = "Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "EPL v1.0"

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

logger = logging.getLogger('nativedroid.server.NativeDroidServer')


class NativeDroidServer(NativeDroidServerServicer):

    def __init__(self, binary_path, native_ss_file, java_ss_file):
        self._binary_path = binary_path
        self._loaded_sos = set()
        self._native_ss_file = native_ss_file
        self._java_ss_file = java_ss_file

    @classmethod
    def from_python_package(cls, binary_path):
        native_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/NativeSourcesAndSinks.txt')
        java_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/TaintSourcesAndSinks.txt')
        return cls(binary_path, native_ss_file, java_ss_file)

    @classmethod
    def from_filesystem(cls, binary_path, native_ss_file, java_ss_file):
        return cls(binary_path, native_ss_file, java_ss_file)

    def GenSummary(self, request, context):
        """
        Gen summary for give method signature.
        :param GenSummaryRequest request: server_pb2.GenSummaryRequest
        :param context:
        :return: server_pb2.GenSummaryResponse
        """
        so_path = request.so_handle
        signature = request.method_signature
        jni_method_name = request.jni_func
        method_signature = method_signature_str(signature)
        jni_method_arguments = get_params_from_method_signature(signature, False)
        arguments_str = ",".join(java_type_str(arg, False) for arg in jni_method_arguments)
        taint_analysis_report, safsu_report, total_instructions = gen_summary(so_path, jni_method_name,
                                                                              method_signature, arguments_str,
                                                                              self._native_ss_file, self._java_ss_file)
        response = GenSummaryResponse(taint=taint_analysis_report, summary=safsu_report,
                                      analyzed_instructions=total_instructions)
        return response

    def LoadBinary(self, request_iterator, context):
        """
        Load given binary file.
        :param request_iterator:
        :param context:
        :return: server_pb2.LoadBinaryResponse
        """
        f = io.BytesIO()
        sha256 = hashlib.sha256()
        for chunk in request_iterator:
            sha256.update(chunk.buffer)
            f.write(chunk.buffer)
        so_digest = sha256.hexdigest()
        so_path = self._binary_path + so_digest

        if so_path not in self._loaded_sos:
            try:
                os.makedirs(self._binary_path)
            except OSError:
                if not os.path.isdir(self._binary_path):
                    raise
            with open(so_path, 'wb') as out:
                out.write(f.getvalue())
            self._loaded_sos.add(so_path)
        size = len(f.getvalue())
        return LoadBinaryResponse(so_handle=so_path, length=size)

    def HasSymbol(self, request, context):
        """
        Check given symbol in the binary file or not.
        :param request:
        :param context:
        :return:
        """
        so_path = request.so_handle
        return HasSymbolResponse(has_symbol=has_symbol(so_path, request.symbol))


def serve(binary_path, native_ss_file, java_ss_file):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_NativeDroidServerServicer_to_server(
        NativeDroidServer.from_filesystem(binary_path, native_ss_file, java_ss_file), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    logger.info('Server started.')
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0)
    logger.info('Server stopped.')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        logger.error('usage: python native_droid_server.py binary_path native_ss_file java_ss_file')
        exit(0)
    serve(sys.argv[1], sys.argv[2], sys.argv[3])