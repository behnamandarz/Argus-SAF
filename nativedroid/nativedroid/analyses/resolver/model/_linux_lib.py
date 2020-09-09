import angr
import claripy
import logging
from nativedroid.analyses.resolver.jni.java_type import *

#from nativedroid.analyses.resolver.annotation.taint_position_annotation import *
#from nativedroid.analyses.resolver.jni.java_type.reference import *

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

nativedroid_logger = logging.getLogger('AndroidLogPrint')
nativedroid_logger.setLevel(logging.INFO)


class Sprintf(angr.SimProcedure):
    """
    __android_log_print SimProcedure.
    """

    def run(self, toPrint, tag, fmt):
        nativedroid_logger.info('SimProcedure: %s', self)
        nativedroid_logger.info('SimProcedure:anot %s', fmt)

        nativedroid_logger.info('SimProcedure:anot %s', fmt.ast.annotations)
        toPrint.ast.annotations = fmt.ast.annotations

        nativedroid_logger.info('SimProcedure:toprint.anotate/topr%s',toPrint)
        nativedroid_logger.info('SimProcedure:__toprint.anot= %s', toPrint.ast.annotations)

        #strlen_simproc = angr.SIM_PROCEDURES['libc']['strlen']
        #fmt_strlen = self.inline_call(strlen_simproc, fmt)

        #fmt_str = self.state.solver.eval(self.state.memory.load(fmt, fmt_strlen.ret_expr), cast_to=str)
        #arg_num = fmt_str.count('%')

        #reg_position = 3
        #stack_position = list()
        #if arg_num > 1:
        #    stack_args_num = arg_num - 1
        #    stack_position = range(1, stack_args_num + 1)
        #jobject = JObject(self.project)
        #return_value = claripy.BVV(jobject.ptr, self.project.arch.bits)
        #return_value = return_value.annotate(
        #   TaintPositionAnnotation(reg_position=reg_position, stack_position=stack_position))
        return 1
    def __repr__(self):
        return '__sprintf'

class Snprintf(angr.SimProcedure):
    """
    __android_log_print SimProcedure.
    """

    def run(self, toPrint,size, tag, fmt):
        nativedroid_logger.info('SimProcedure: %s', self)

        nativedroid_logger.info('SimProcedure:anot %s', fmt.ast)
        nativedroid_logger.info('SimProcedure:anot %s', fmt.annotations)
        nativedroid_logger.info('SimProcedure:anot %s', toPrint)


        #toPrint=fmt
        toPrint.ast.annotations = fmt.ast.annotations

        #nativedroid_logger.info('SimProcedure:toprint.anotate/topr%s',toPrint)
        nativedroid_logger.info('SimProcedure:__toprint.anot= %s', toPrint.ast.annotations)

        #strlen_simproc = angr.SIM_PROCEDURES['libc']['strlen']
        #fmt_strlen = self.inline_call(strlen_simproc, fmt)

        #fmt_str = self.state.solver.eval(self.state.memory.load(fmt, fmt_strlen.ret_expr), cast_to=str)
        #arg_num = fmt_str.count('%')

        #reg_position = 3
        #stack_position = list()
        #if arg_num > 1:
        #    stack_args_num = arg_num - 1
        #    stack_position = range(1, stack_args_num + 1)
        #jobject = JObject(self.project)
        #return_value = claripy.BVV(jobject.ptr, self.project.arch.bits)
        #return_value = return_value.annotate(
        #   TaintPositionAnnotation(reg_position=reg_position, stack_position=stack_position))
        return 1
    def __repr__(self):
        return '__snprintf'

class Strcpy(angr.SimProcedure):
    """
    __android_log_print SimProcedure.
    """

    def run(self, dest, src):
        nativedroid_logger.info('SimProcedure: %s', self)

        nativedroid_logger.info('SimProcedure:anot %s', src.annotations[0])
        nativedroid_logger.info('SimProcedure:anot %s', dest.annotations)
        dest=src
        dest.ast.annotations=src.ast.annotations
        nativedroid_logger.info('SimProcedure:anotdest %s', dest.annotations)

        #toPrint = fmt[0]

        #nativedroid_logger.info('SimProcedure:toprint.anotate/topr%s',toPrint)
        #nativedroid_logger.info('SimProcedure:__toprint.anot= %s', toPrint.annotations)

        #strlen_simproc = angr.SIM_PROCEDURES['libc']['strlen']
        #fmt_strlen = self.inline_call(strlen_simproc, fmt)

        #fmt_str = self.state.solver.eval(self.state.memory.load(fmt, fmt_strlen.ret_expr), cast_to=str)
        #arg_num = fmt_str.count('%')

        #reg_position = 3
        #stack_position = list()
        #if arg_num > 1:
        #    stack_args_num = arg_num - 1
        #    stack_position = range(1, stack_args_num + 1)
        #jobject = JObject(self.project)
        #return_value = claripy.BVV(jobject.ptr, self.project.arch.bits)
        #return_value = return_value.annotate(
        #   TaintPositionAnnotation(reg_position=reg_position, stack_position=stack_position))
        return dest
    def __repr__(self):
        return '__strcpy'

class Strncpy(angr.SimProcedure):
    """
    __android_log_print SimProcedure.
    """

    def run(self, dest, src , size):
        nativedroid_logger.info('SimProcedure: %s', self)
        print ("srcDest",src.to_claripy() , dest.ast.args)
        nativedroid_logger.info('SimProcedure:anot %s', src.annotations[0])
        nativedroid_logger.info('SimProcedure:anot %s', dest.annotations)
        #dest =src
        print ("srcDest",src,dest)

        dest.ast.annotations=src.ast.annotations
        nativedroid_logger.info('SimProcedure:anotdest %s', dest.annotations)

        #toPrint = fmt[0]

        #nativedroid_logger.info('SimProcedure:toprint.anotate/topr%s',toPrint)
        #nativedroid_logger.info('SimProcedure:__toprint.anot= %s', toPrint.annotations)

        #strlen_simproc = angr.SIM_PROCEDURES['libc']['strlen']
        #fmt_strlen = self.inline_call(strlen_simproc, fmt)

        #fmt_str = self.state.solver.eval(self.state.memory.load(fmt, fmt_strlen.ret_expr), cast_to=str)
        #arg_num = fmt_str.count('%')

        #reg_position = 3
        #stack_position = list()
        #if arg_num > 1:
        #    stack_args_num = arg_num - 1
        #    stack_position = range(1, stack_args_num + 1)
        #jobject = JObject(self.project)
        #return_value = claripy.BVV(jobject.ptr, self.project.arch.bits)
        #return_value = return_value.annotate(
        #   TaintPositionAnnotation(reg_position=reg_position, stack_position=stack_position))
        return dest
    def __repr__(self):
        return '__strncpy'

class Strcat(angr.SimProcedure):
    """
    __android_log_print SimProcedure.
    """

    def run(self, dest, src):
        nativedroid_logger.info('SimProcedure: %s', self)

        nativedroid_logger.info('SimProcedure:anot %s', src.annotations[0])
        nativedroid_logger.info('SimProcedure:anot %s', dest.annotations)
        dest.ast.annotations=src.ast.annotations
        dest.annotations=src.annotations
        nativedroid_logger.info('SimProcedure:anotdest %s', dest.annotations)

        #toPrint = fmt[0]

        #nativedroid_logger.info('SimProcedure:toprint.anotate/topr%s',toPrint)
        #nativedroid_logger.info('SimProcedure:__toprint.anot= %s', toPrint.annotations)

        #strlen_simproc = angr.SIM_PROCEDURES['libc']['strlen']
        #fmt_strlen = self.inline_call(strlen_simproc, fmt)

        #fmt_str = self.state.solver.eval(self.state.memory.load(fmt, fmt_strlen.ret_expr), cast_to=str)
        #arg_num = fmt_str.count('%')

        #reg_position = 3
        #stack_position = list()
        #if arg_num > 1:
        #    stack_args_num = arg_num - 1
        #    stack_position = range(1, stack_args_num + 1)
        #jobject = JObject(self.project)
        #return_value = claripy.BVV(jobject.ptr, self.project.arch.bits)
        #return_value = return_value.annotate(
        #   TaintPositionAnnotation(reg_position=reg_position, stack_position=stack_position))
        return dest
    def __repr__(self):
        return '__strcat'

class Strncat(angr.SimProcedure):
    """
    __android_log_print SimProcedure.
    """

    def run(self, dest, src,size):
        nativedroid_logger.info('SimProcedure: %s', self)

        nativedroid_logger.info('SimProcedure:anot %s', src.annotations[0])
        nativedroid_logger.info('SimProcedure:anot %s', dest.annotations)
        dest.ast.annotations=src.ast.annotations
        #dest.annotations=src.annotations
        nativedroid_logger.info('SimProcedure:anotdest %s', dest.annotations)

        #toPrint = fmt[0]

        #nativedroid_logger.info('SimProcedure:toprint.anotate/topr%s',toPrint)
        #nativedroid_logger.info('SimProcedure:__toprint.anot= %s', toPrint.annotations)

        #strlen_simproc = angr.SIM_PROCEDURES['libc']['strlen']
        #fmt_strlen = self.inline_call(strlen_simproc, fmt)

        #fmt_str = self.state.solver.eval(self.state.memory.load(fmt, fmt_strlen.ret_expr), cast_to=str)
        #arg_num = fmt_str.count('%')

        #reg_position = 3
        #stack_position = list()
        #if arg_num > 1:
        #    stack_args_num = arg_num - 1
        #    stack_position = range(1, stack_args_num + 1)
        #jobject = JObject(self.project)
        #return_value = claripy.BVV(jobject.ptr, self.project.arch.bits)
        #return_value = return_value.annotate(
        #   TaintPositionAnnotation(reg_position=reg_position, stack_position=stack_position))
        return dest
    def __repr__(self):
        return '__strncat'
