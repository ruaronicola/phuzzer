from . import Phuzzer
from ..util import hexescape
from ..errors import InstallError
from collections import defaultdict
from glob import glob
import shellphish_afl
import subprocess
import contextlib
import itertools
import logging
import signal
import shutil
import angr
import os

l = logging.getLogger("phuzzer.phuzzers.afl")
l.setLevel(logging.DEBUG)


class AFL(Phuzzer):
    """ Phuzzer object, spins up a fuzzing job on a binary """

    def __init__(
        self, target, seeds=None, dictionary=None, create_dictionary=None,
        work_dir=None, seeds_dir=None, resume=False,
        afl_count=1, memory="8G", timeout=None,
        library_path=None, target_opts=None, extra_opts=None,
        crash_mode=False, use_qemu=True, fuzzer_name="fuzzer-master",
        run_timeout=None
    ):
        """
        :param binary_path: path to the binary to fuzz. List or tuple for multi-CB.
        :param seeds: list of inputs to seed fuzzing with
        :param dictionary: a list of bytes objects to seed the dictionary with
        :param create_dictionary: create a dictionary from the string references in the binary

        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here
        :param resume: resume the prior run, if possible

        :param memory: AFL child process memory limit (default: "8G")
        :param afl_count: number of AFL jobs total to spin up for the binary
        :param timeout: timeout for individual runs within AFL

        :param library_path: library path to use, if none is specified a default is chosen
        :param target_opts: extra options to pass to the target
        :param extra_opts: extra options to pass to AFL when starting up

        :param crash_mode: if set to True AFL is set to crash explorer mode, and seed will be expected to be a crashing input
        :param use_qemu: Utilize QEMU for instrumentation of binary.
        """
        super().__init__(target, seeds=seeds, dictionary=dictionary, create_dictionary=create_dictionary, timeout=timeout)

        self.work_dir = work_dir or os.path.join("/tmp", "phuzzer", os.path.basename(str(target)))
        if resume and os.path.isdir(self.work_dir):
            self.in_dir = "-"
        else:
            l.info("could resume, but starting over upon request")
            if fuzzer_name == "fuzzer-master":
                with contextlib.suppress(FileNotFoundError):
                    shutil.rmtree(self.work_dir)
            self.in_dir = seeds_dir or os.path.join(self.work_dir, "initial_seeds")
            with contextlib.suppress(FileExistsError):
                os.makedirs(self.in_dir)

        self.afl_count      = afl_count
        self.memory         = memory

        self.library_path   = library_path
        self.target_opts    = target_opts or [ ]
        self.extra_opts     = extra_opts if type(extra_opts) is list else extra_opts.split() if type(extra_opts) is str else [ ]

        self.crash_mode     = crash_mode
        self.use_qemu       = use_qemu

        self.run_timeout = run_timeout

        self.mutator = itertools.cycle([
                ["-R"],         # radamsa mutator
                ["-L", "10"],   # MOpt(imize) mode
                ["-c", "0"],     # CMPLOG mode
            ])
        self.power_schedule = itertools.cycle(['fast', 'explore', 'coe', 'mmopt'])

        self.target_name = os.path.basename(self.target)
        self.target_os = None
        self.target_arch = None

        # sanity check crash mode
        if self.crash_mode:
            if seeds is None:
                raise ValueError("Seeds must be specified if using the fuzzer in crash mode")
            l.info("AFL will be started in crash mode")

        # set up the paths
        self.afl_path = self.choose_afl()
        
        # queue.all and cmin dirs 
        self.queue_all_dir = os.path.join(self.work_dir, 'queue.all')
        self.queue_min_dir = f"/data/afl/queue.cmin/{self.target_name}"
        

    #
    # Overrides
    #

    def create_dictionary(self):
        d = super().create_dictionary()

        # AFL has a limit of 128 bytes per dictionary entries
        valid_strings = []
        for s in d:
            if len(s) <= 128:
                valid_strings.append(s)
            for s_atom in s.split():
                if len(s_atom) <= 128:
                    valid_strings.append(s_atom)
                else:
                    valid_strings.append(s[:128])

        return valid_strings

    #
    # AFL functionality
    #

    @property
    def dictionary_file(self):
        return os.path.join(self.work_dir, "dict.txt")

    def start(self):
        """
        start fuzzing
        """

        super().start()

        # create the directory
        with contextlib.suppress(FileExistsError):
            os.makedirs(self.work_dir)

        # write the dictionary
        if self.dictionary:
            with open(self.dictionary_file, "w") as df:
                for i,s in enumerate(set(self.dictionary)):
                    s_val = hexescape(s)
                    df.write("string_%d=\"%s\"" % (i, s_val) + "\n")

        # write the seeds
        if self.in_dir != "-":
            if not self.seeds:
                l.warning("No seeds provided - using 'fuzz'")
            template = os.path.join(self.in_dir, "seed-%d")
            for i, seed in enumerate(self.seeds or [ b"fuzz" ]):
                with open(template % i, "wb") as f:
                    f.write(seed)

        # spin up the master AFL instance
        master = self._start_afl_instance() # the master fuzzer
        self.processes.append(master)

        # only spins up an AFL instances if afl_count > 1
        for _ in range(1, self.afl_count):
            self.processes.append(self._start_afl_instance())

        return self

    @property
    def alive(self):
        if not len(self.stats):
            return False

        alive_cnt = 0
        for fuzzer in self.stats:
            try:
                os.kill(int(self.stats[fuzzer]['fuzzer_pid']), 0)
                alive_cnt += 1
            except (OSError, KeyError):
                pass

        return bool(alive_cnt)

    @property
    def summary_stats(self):
        stats = self.stats
        summary_stats = defaultdict(lambda: 0)
        for _, fuzzstats in stats.items():
            for fstat, value in fuzzstats.items():
                try:
                    fvalue = float(value)
                    summary_stats[fstat] += fvalue
                except ValueError:
                    pass
        return summary_stats

    @property
    def stats(self):

        # collect stats into dictionary
        stats = {}
        if os.path.isdir(self.work_dir):
            for fuzzer_dir in os.listdir(self.work_dir):
                stat_path = os.path.join(self.work_dir, fuzzer_dir, "fuzzer_stats")
                if os.path.isfile(stat_path):
                    stats[fuzzer_dir] = {}

                    with open(stat_path, "r") as f:
                        stat_blob = f.read()
                        stat_lines = stat_blob.split("\n")[:-1]
                        for stat in stat_lines:
                            key, val = stat.split(":")
                            stats[fuzzer_dir][key.strip()] = val.strip()

        return stats

    #
    # Helpers
    #

    def _get_crashing_inputs(self, signals):
        """
        Retrieve the crashes discovered by AFL. Only return those crashes which
        recieved a signal within 'signals' as the kill signal.

        :param signals: list of valid kill signal numbers
        :return: a list of strings which are crashing inputs
        """

        crashes = set()
        for fuzzer in os.listdir(self.work_dir):
            crashes_dir = os.path.join(self.work_dir, fuzzer, "crashes")

            if not os.path.isdir(crashes_dir):
                # if this entry doesn't have a crashes directory, just skip it
                continue

            for crash in os.listdir(crashes_dir):
                if crash == "README.txt":
                    # skip the readme entry
                    continue

                attrs = dict(map(lambda x: (x[0], x[-1]), map(lambda y: y.split(":"), crash.split(","))))

                if int(attrs['sig']) not in signals:
                    continue

                crash_path = os.path.join(crashes_dir, crash)
                with open(crash_path, 'rb') as f:
                    crashes.add(f.read())

        return list(crashes)

    #
    # AFL-specific
    #

    def bitmap(self, fuzzer='fuzzer-master'):
        """
        retrieve the bitmap for the fuzzer `fuzzer`.
        :return: a string containing the contents of the bitmap.
        """

        if not fuzzer in os.listdir(self.work_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        bitmap_path = os.path.join(self.work_dir, fuzzer, "fuzz_bitmap")

        bdata = None
        try:
            with open(bitmap_path, "rb") as f:
                bdata = f.read()
        except IOError:
            pass

        return bdata

    #
    # Interface
    #

    @staticmethod
    def _check_environment():
        err = ""
        # check for afl sensitive settings
        with open("/proc/sys/kernel/core_pattern") as f:
            if not "core" in f.read():
                err += "!!!! AFL ERROR: Pipe at the beginning of core_pattern\n"
                err += "++++ TO FIX THIS, LITERALLY JUST EXECUTE THIS COMMAND:\n"
                err += "     echo core | sudo tee /proc/sys/kernel/core_pattern\n"

        # This file is based on a driver not all systems use
        # http://unix.stackexchange.com/questions/153693/cant-use-userspace-cpufreq-governor-and-set-cpu-frequency
        # TODO: Perform similar performance check for other default drivers.
        if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"):
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
                if not "performance" in f.read():
                    err += "!!!! AFL ERROR: Suboptimal CPU scaling governor\n"
                    err += "++++ TO FIX THIS, LITERALLY JUST EXECUTE THIS COMMAND:\n"
                    err += "    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor\n"

        # TODO: test, to be sure it doesn't mess things up
        with open("/proc/sys/kernel/sched_child_runs_first") as f:
            if not "1" in f.read():
                err += "!!!! AFL WARNING: We probably want the fork() children to run first\n"
                err += "++++ TO FIX THIS, LITERALLY JUST EXECUTE THIS COMMAND:\n"
                err += "     echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first\n"

        if err:
            afl_dir = shellphish_afl.afl_dir('linux')
            configpath = os.path.join(afl_dir, "afl-system-config")
            err += "!!!! AFL WARNING: The environment was not properly configured\n"
            err += "++++ TO FIX THIS, LITERALLY JUST EXECUTE THIS COMMAND:\n"
            err += "     sudo sh "+configpath+"\n"
            err += "++++ YOU MAY ALSO ADD TO /etc/default/grub:\n"
            err += "     GRUB_CMDLINE_LINUX_DEFAULT='ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off'"
            raise InstallError(err)

    def add_core(self):
        """
        add one fuzzer
        """

        self.processes.append(self._start_afl_instance())

    def remove_core(self):
        """
        remove one fuzzer
        """

        try:
            f = self.processes.pop()
        except IndexError:
            l.error("no fuzzer to remove")
            raise ValueError("no fuzzer to remove")

        f.kill()

    def crashes(self, signals=(signal.SIGSEGV, signal.SIGILL)):
        """
        Retrieve the crashes discovered by AFL. Since we are now detecting flag
        page leaks (via SIGUSR1) we will not return these leaks as crashes.
        Instead, these 'crashes' can be found with the leaks function.

        :param signals: list of valid kill signal numbers to override the default (SIGSEGV and SIGILL)
        :return: a list of strings which are crashing inputs
        """

        return self._get_crashing_inputs(signals)

    def queue(self, fuzzer='fuzzer-master'):
        """
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        """

        if not fuzzer in os.listdir(self.work_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        queue_path = os.path.join(self.work_dir, fuzzer, 'queue')
        queue_files = list(filter(lambda x: x != ".state", os.listdir(queue_path)))

        queue_l = [ ]
        for q in queue_files:
            with open(os.path.join(queue_path, q), 'rb') as f:
                queue_l.append(f.read())

        return queue_l

    def pollenate(self, *testcases):
        """
        pollenate a fuzzing job with new testcases

        :param testcases: list of bytes objects representing new inputs to introduce
        """

        nectary_queue_directory = os.path.join(self.work_dir, 'pollen', 'queue')
        if not 'pollen' in os.listdir(self.work_dir):
            os.makedirs(nectary_queue_directory)

        pollen_cnt = len(os.listdir(nectary_queue_directory))

        for tcase in testcases:
            with open(os.path.join(nectary_queue_directory, "id:%06d,src:pollenation" % pollen_cnt), "wb") as f:
                f.write(tcase)

            pollen_cnt += 1
            
    def cmin(self, fuzzer_prefix="fuzzer-"):
        afl_dir = shellphish_afl.afl_dir(self.target_os)
        afl_path_var = shellphish_afl.afl_path_var(self.target_arch)
        os.environ['AFL_PATH'] = afl_path_var
        
        # create queue.all dir
        if os.path.exists(self.queue_all_dir):
            shutil.rmtree(self.queue_all_dir)
        os.makedirs(self.queue_all_dir)
        
        # copy all seeds
        for seed in glob(f"{self.work_dir}/{fuzzer_prefix}*/queue/id:*"):
            id = seed.split("/")[-1]
            fuzzer = seed.split("/queue")[0].split("/")[-1]
            shutil.copy(seed, f"{self.queue_all_dir}/{{{fuzzer}}}{id}")
        
        # create queue.cmin
        if os.path.exists(self.queue_min_dir):
            shutil.rmtree(self.queue_min_dir)
        os.makedirs(self.queue_min_dir)
        
        # create cmd args
        cmin_path = os.path.join(afl_dir, "afl-cmin")
        args = [cmin_path]
        
        args += ["-i", self.queue_all_dir]
        args += ["-o", self.queue_min_dir]
        args += ["-m", self.memory]
        args += ["-Q"]
        args += ["--"]
        args += [self.target]
        args += self.target_opts
        
        #l.debug(f"execing: AFL_PATH={afl_path_var} {' '.join(args)}")
        return subprocess.Popen(args, env=os.environ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        

    #
    # AFL launchers
    #

    def _start_afl_instance(self):

        args = [self.afl_path]

        if len(self.processes) == 0:
            fuzzer_id = "fuzzer-master"
            args += ["-M", fuzzer_id]
        else:
            fuzzer_id = "fuzzer-%d" % len(self.processes)
            args += ["-S", fuzzer_id]

        if not os.path.exists(f"{self.work_dir}/{fuzzer_id}/queue"):
            self.in_dir = os.path.join(self.work_dir, "initial_seeds")

        args += ["-i", self.in_dir]
        args += ["-o", self.work_dir]
        args += ["-m", self.memory]
        args += ["-p", next(self.power_schedule)]
        args += next(self.mutator)

        if self.use_qemu:
            args += ["-Q"]

        if self.crash_mode:
            args += ["-C"]

        if os.path.exists(self.dictionary_file):
            args += ["-x", self.dictionary_file]

        args += self.extra_opts

        if self.run_timeout is not None:
            args += ["-t", "%d+" % self.run_timeout]
        args += ["--"]
        args += [self.target]
        args += [o.strip(' ') for o in self.target_opts]

        with open(os.path.join(self.work_dir, fuzzer_id+".cmd"), "w") as cf:
            cf.write(" ".join(args) + "\n")

        logpath = os.path.join(self.work_dir, fuzzer_id + ".log")
        l.debug("execing: %s > %s", ' '.join(args), logpath)
        with open(logpath, "w") as fp:
            return subprocess.Popen(args, stdout=fp, stderr=fp, close_fds=True)
        
    def choose_afl(self):
        """
        Chooses the right AFL and sets up some environment.
        """

        # set up the AFL path
        self.proj = self.proj or angr.Project(self.target, auto_load_libs=False)
        self.target_os = self.proj.loader.main_object.os
        self.target_arch = self.proj.arch.qemu_name

        afl_dir = shellphish_afl.afl_dir(self.target_os)
        afl_path_var = shellphish_afl.afl_path_var(self.target_arch)
        
        directory = None
        if self.target_arch == "i386":
            directory = "i386"
            qemu_base = 0x40000000
        if self.target_arch == "x86_64":
            directory = "x86_64"
            qemu_base = 0x4000000000

        if directory is None:
            l.warning("architecture \"%s\" has no installed libraries", self.target_arch)
        elif False:  # for now, avoid mixing up libs
            libpath = os.path.join(afl_dir, "..", "fuzzer-libs", directory)

            l.debug("exporting QEMU_LD_PREFIX=%s", libpath)
            os.environ['QEMU_LD_PREFIX'] = libpath

        l.debug("exporting AFL_PATH=%s", afl_path_var)
        os.environ['AFL_PATH'] = afl_path_var

        libcompcovpath = os.path.join(afl_dir, "libcompcov.so")
        libdislocatorpath = os.path.join(afl_dir, "libdislocator.so")
        afl_preload = " ".join([libcompcovpath, libdislocatorpath])
        afl_preload = f"'{afl_preload}'"
        l.debug("exporting AFL_PRELOAD=%s", afl_preload)
        os.environ['AFL_PRELOAD'] = afl_preload

        l.debug("exporting AFL_COMPCOV_LEVEL=2")
        os.environ['AFL_COMPCOV_LEVEL'] = "2"  # CompareCoverage instrumentation

        # set entrypoint
        main = self.proj.loader.find_symbol('main')
        entrypoint = main.rebased_addr if main else self.proj.entry
        
        if self.proj.loader.main_object.pic:
            entrypoint = self.proj.loader.main_object.addr_to_offset(entrypoint)
            entrypoint += qemu_base

        #l.debug("exporting QEMU_SET_ENV=%s", f"QEMU_GUEST_BASE={hex(qemu_base)}")
        os.environ['QEMU_SET_ENV'] = f"QEMU_GUEST_BASE={hex(qemu_base)}"
        
        l.debug("exporting AFL_ENTRYPOINT=%s", hex(entrypoint))
        os.environ['AFL_ENTRYPOINT'] = hex(entrypoint)
        
        #if not self.proj.loader.main_object.pic:
        #l.debug("exporting AFL_QEMU_PERSISTENT_ADDR=%s", hex(entrypoint))
        #os.environ['AFL_QEMU_PERSISTENT_ADDR'] = hex(entrypoint)
        #os.environ['AFL_QEMU_PERSISTENT_GPR'] = "1"

        # return the AFL path
        return shellphish_afl.afl_bin(self.target_os)
