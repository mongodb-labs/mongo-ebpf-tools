""" module that can generate c-style eBPF programs
    given a list of probes to attach to and their arguments """
from .consts import *

def reduce(fn, items):
    return ''.join(map(fn, items))

class Probe:
    """ Representation of a probe specification useful for code generation. """
    def __init__(self, probe_dict):
        assert isinstance(probe_dict, dict)

        self.name = probe_dict[PROBE_NAME_KEY]
        assert isinstance(self.name, str)

        self.hits = probe_dict.get(PROBE_HIT_KEY, 0)
        assert isinstance(self.hits, int)

        if PROBE_ARGS_KEY in probe_dict:
            self.args = [Arg(arg, self.hits, self.name, index)
                            for index, arg in enumerate(probe_dict[PROBE_ARGS_KEY])]
        else:
            self.args = []

        self.function_name = PROBE_FN_NAME.format(self.name)
        self.output_struct_name = BPF_PERF_OUTPUT_STRUCT_NAME.format(self.name)

    def before_output_gen(self):
        return reduce(Arg.before_output_gen, self.args)

    def bpf_perf_output_gen(self):
        c_prog = BPF_PERF_OUTPUT.format(self.name)
        fields = BPF_PERF_OUTPUT_COMMON_MEMBER_DECLS + reduce(Arg.get_output_struct_def, self.args)
        c_prog += STRUCT.format(self.output_struct_name, fields)
        return c_prog

    def entry_fn_gen(self):
        fn_content = STRUCT_INIT.format(self.output_struct_name, BPF_OUT_NAME)
        fn_content += BPF_PERF_OUTPUT_COMMON
        fn_content += reduce(Arg.fill_output_struct, self.args)
        fn_content += BPF_PERF_SUBMIT_STMT.format(self.name)
        return PROBE_ENTRY_FN.format(self.function_name, fn_content)

class Arg:
    """ Representation of an argument to a Probe,
        holding information about where it can be located. """
    def __init__(self, arg_dict, num_hits, probe_name, index, depth=0):
        assert isinstance(arg_dict, dict)

        self.type = arg_dict[ARG_TYPE_KEY]
        assert self.type in (STRING_TYPE, STRUCT_TYPE, INT_TYPE, POINTER_TYPE)

        self.probe_name = probe_name
        assert isinstance(self.probe_name, str)

        self.depth = depth
        assert isinstance(self.depth, int)

        self.index = index
        assert isinstance(self.index, int)

        if ARG_NAME_KEY in arg_dict:
            self.name = arg_dict[ARG_NAME_KEY]
            self.output_arg_name = self.name
            self.output_addr_name = self.name
        else:
            self.name = None
            self.output_arg_name = BPF_PERF_OUTPUT_ARG_NAME.format(self.depth, self.index)
            self.output_addr_name = BPF_PERF_OUTPUT_ADDR_NAME.format(self.depth, self.index)

        if self.type == STRING_TYPE:
            self.length = arg_dict[ARG_STR_LEN_KEY]
            assert isinstance(self.length, int)
        else:
            self.length = 0

        if self.type == STRUCT_TYPE:
            self.output_struct_name = STRUCT_NAME.format(arg_name = self.output_arg_name,
                                                         probe_name = self.probe_name,
                                                         depth = self.depth,
                                                         index = self.index)

            self.fields = [Arg(val, num_hits, probe_name, child_index, depth=depth+1)
                            for child_index, val in enumerate(arg_dict[ARG_STRUCT_FIELDS_KEY])]

            for field in self.fields:
                if field.name != None:
                    field.output_arg_name += ARG_NAME_CAT.format(self.index)
                    field.output_addr_name += ARG_NAME_CAT.format(self.index)

    def get_c_decl(self):
        """ Returns the type and name of this argument in a C program.
            The name should be unique to an instance but the same across instances. """
        return TYPE_DECL[self.type].format(probe_name = self.probe_name,
                                           arg_name = self.output_arg_name,
                                           depth = self.depth,
                                           index = self.index,
                                           length = self.length)

    def before_output_gen(self):
        """ Returns a string of any code that needs to be emitted before the output struct
            containing this argument is emitted. This allows structs to print their definitions
            (and any nested definitions) before they are referenced. """
        if self.type != STRUCT_TYPE:
            return ''

        members = ''
        result = ''
        for member in self.fields:
            result += member.before_output_gen()
            members += STRUCT_MEMBER.format(member.get_c_decl())
        result += STRUCT.format(self.output_struct_name, members)

        return result

    def get_output_struct_def(self):
        """ Returns what members in the output struct this arg is responsible for. """
        if self.type != STRUCT_TYPE:
            return STRUCT_MEMBER.format(self.get_c_decl())

        return reduce(Arg.get_output_struct_def, self.fields)

    def fill_output_struct(self, source_struct_name=None):
        """ Returns the code necessary to fill the members of the output struct
            that this arg is responsible for. """
        if source_struct_name:
            # we should be reading our value out of a struct
            if self.type == STRING_TYPE:
                # Can't access C runtime (strcpy, etc) and there are no loops.
                # Thus, to copy strings from embedded structs to the output struct, the offset
                # within the passed in struct is determined, and then a bpf_probe_read_str is
                # issued, reading the string from userspace once more.
                # For updates on string builtin functions, see:
                # https://github.com/iovisor/bcc/issues/691
                result = BPF_READ_STRUCT_MEMBER_STR.format(
                            source = source_struct_name + "." + self.output_arg_name,
                            target = self.output_arg_name,
                            str_addr_name = self.output_addr_name)
                return result

            elif self.type == STRUCT_TYPE:
                # add ourselves to the source struct name for our fields to read out of
                result = ''
                source_struct_name = source_struct_name + "." + self.output_arg_name
                for arg in self.fields:
                    result += arg.fill_output_struct(source_struct_name) + '\n'

                return result

            return BPF_PERF_OUTPUT_MEMBER_ASSN.format(
                        target=self.output_arg_name,
                        source_struct=source_struct_name,
                        source_struct_member=self.output_arg_name)

        elif self.type == STRING_TYPE:
            assert self.depth == 0
            # read the addr out of the USDT arg and read the C-string into our output struct
            return BPF_READ_STR.format(
                        probe_name=self.probe_name,
                        arg_num=self.index + 1,
                        addr_name=self.output_addr_name,
                        out_member=self.output_arg_name)

        elif self.type == STRUCT_TYPE:
            assert self.depth == 0
            # read in the struct from the USDT arg pointer
            struct_name = BASE_STRUCT_NAME.format(probe_name=self.probe_name, index=self.index)
            result = BPF_READ_STRUCT.format(probe_name=self.probe_name,
                                            index=self.index,
                                            struct_name=struct_name,
                                            arg_num=self.index + 1)

            for arg in self.fields:
                result += arg.fill_output_struct(struct_name) + '\n'
            return result

        else:
            # read the argument directly
            return BPF_READ_ARG.format(num=self.index + 1, output_member_name=self.output_arg_name)

class Generator:
    """ Responsible for orchestrating the generation of code
        for each probe that gets added to it. """
    def __init__(self):
        self.c_prog = HEADERS

    def finish(self):
        """ Do any clean up work and then provide the generated C program. """
        return self.c_prog

    def add_probe(self, probe):
        """ Add a probe and generate code to attach that probe
            to its own output channel and function. """
        assert isinstance(probe, Probe)

        self.c_prog += probe.before_output_gen()
        self.c_prog += probe.bpf_perf_output_gen()
        self.c_prog += probe.entry_fn_gen()
