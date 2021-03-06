#!/usr/bin/env python

import os
import imp
import time
import shutil
import signal
import socket
import driller
import tarfile
import argparse
import importlib
import logging.config

from glob import glob

from .timer import InfiniteTimer
from . import AFL
from . import GreaseCallback

from driller.prioritization_techniques import UniqueSearch, HardestSearch, SyMLSearch

def main():
    parser = argparse.ArgumentParser(description="Shellphish fuzzer interface")
    parser.add_argument('binary', help="the path to the target binary to fuzz")
    parser.add_argument('-o','--opts', nargs='+', help="Command line options", required=False)
    parser.add_argument('-g', '--grease-with', help="A directory of inputs to grease the fuzzer with when it gets stuck.")
    parser.add_argument('-d', '--driller_workers', help="When the fuzzer gets stuck, drill with N workers.", type=int)
    parser.add_argument('-f', '--force_interval', help="Force greaser/fuzzer assistance at a regular interval (in seconds).", type=float)
    parser.add_argument('-w', '--work-dir', help="The work directory for AFL.", default="/dev/shm/work/")
    parser.add_argument('-c', '--afl-cores', help="Number of AFL workers to spin up.", default=1, type=int)
    parser.add_argument('-C', '--first-crash', help="Stop on the first crash.", action='store_true', default=False)
    parser.add_argument('-t', '--timeout', help="Timeout (in seconds).", type=float, default=None)
    parser.add_argument('-i', '--ipython', help="Drop into ipython after starting the fuzzer.", action='store_true')
    parser.add_argument('-T', '--tarball', help="Tarball the resulting AFL workdir for further analysis to this file -- '{}' is replaced with the hostname.")
    parser.add_argument('-m', '--helper-module', help="A module that includes some helper scripts for seed selection and such.")
    parser.add_argument('--memory', help="Memory limit to pass to AFL (MB, or use k, M, G, T suffixes)", default="8G")
    parser.add_argument('-r', '--resume', help="Resume fuzzers, if possible.", action='store_true', default=False)
    parser.add_argument('--technique', help="Prioritization technique for driller exploration.", default="unique")
    parser.add_argument('--classifier', help="Classifier for SyML exploration.")
    parser.add_argument('--no-dictionary', help="Do not create a dictionary before fuzzing.", action='store_true', default=False)
    parser.add_argument('--dictionary', help="Path to custom dictionary.")
    parser.add_argument('--logcfg', help="The logging configuration file.", default=".shellphuzz.ini")
    parser.add_argument('-s', '--seed-dir', action="append", help="Directory of files to seed fuzzer with")
    parser.add_argument('--run-timeout', help="Number of milliseconds permitted for each run of binary", type=int, default=None)
    parser.add_argument('--driller-timeout', help="Number of seconds to allow driller to run", type=int, default=99999*60)
    parser.add_argument('--length-extension', help="Try extending inputs to driller by this many bytes", type=int)
    args = parser.parse_args()

    status = {'start_time' : time.time(), 'abort_crash' : False, 'abort_program' : False, 'abort_tmout' : False}

    if os.path.isfile(os.path.join(os.getcwd(), args.logcfg)):
        logging.config.fileConfig(os.path.join(os.getcwd(), args.logcfg))

    helper_module = None
    if args.helper_module:
        try:
            helper_module = importlib.import_module(args.helper_module)
        except (ImportError, TypeError):
            helper_module = imp.load_source('fuzzing_helper', args.helper_module)

    seeds = None
    if args.seed_dir:
        print("[*] Seeding...")
        seeds = [open(s, 'rb').read() for d in args.seed_dir for s in glob(f"{d}/*") if os.path.isfile(s)]

    dictionary = None
    if args.dictionary:
        print(f"[*] Reading custom dictionary from file {args.dictionary}...")
        with open("jpeg.dict", "r", encoding='unicode_escape') as f:
            dictionary = f.read().encode('raw_unicode_escape').splitlines()

    print("[*] Creating fuzzer...")
    status['fuzzer'] = AFL(
        args.binary, target_opts=args.opts, work_dir=args.work_dir, seeds=seeds, afl_count=args.afl_cores,
        create_dictionary=not args.no_dictionary, dictionary=dictionary, 
        timeout=args.timeout, memory=args.memory, run_timeout=args.run_timeout, resume=args.resume
    )

    ### STUCK CALLBACK ###
    drill_extension = None
    grease_extension = None
    if args.grease_with:
        print("[*] Greasing...")
        grease_extension = GreaseCallback(
            args.grease_with,
            grease_filter=helper_module.grease_filter if helper_module is not None else None,
            grease_sorter=helper_module.grease_sorter if helper_module is not None else None)
    if args.driller_workers:
        print("[*] Drilling...")
        print(f"[*] Using technique {args.technique}")
        technique = {"unique":UniqueSearch, "hard":HardestSearch, "syml":SyMLSearch}[args.technique]
        drill_extension = driller.LocalCallback(
            num_workers=args.driller_workers, worker_timeout=args.driller_timeout, 
            length_extension=args.length_extension, technique=technique)
    
    stuck_callback = (
        (lambda f: (grease_extension(f), drill_extension(f))) if drill_extension and grease_extension
        else drill_extension or grease_extension
    )
    def _stuck_callback():
        stuck_callback(status['fuzzer'])
    _timer = InfiniteTimer(args.force_interval, _stuck_callback)
    
    # start it!
    print("[*] Starting fuzzer...")
    status['fuzzer'].start()
    if args.force_interval: _timer.start()

    if args.classifier:
        os.system(f"mkdir -p {args.work_dir}/driller/")
        os.system(f"cp {args.classifier} {args.work_dir}/driller/classifier.pkl")
        print(f"[*] Using classifier {args.classifier}")

    ### STATUS CALLBACK ###
    def status_callback(status):
        elapsed_time = time.time() - status['start_time']
        status_str = build_status_str(elapsed_time, args.first_crash, args.timeout, args.afl_cores, status['fuzzer'])
        print(status_str, end="\r")
        if args.first_crash and status['fuzzer'].found_crash():
            status['abort_crash'] = True
        if "PROGRAM ABORT" in open(f"{status['fuzzer'].work_dir}/fuzzer-master.log").read():
            status['abort_program'] = True
        if status['fuzzer'].timed_out():
            status['abort_tmout'] = True
    def _status_callback():
        try: status_callback(status)
        except: pass
    InfiniteTimer(1, _status_callback).start()
    

    if args.ipython:
        print("[!]")
        print("[!] Launching ipython shell. Relevant variables:")
        print("[!]")
        print("[!] fuzzer")
        print("[!] driller_extension")
        print("[!] grease_extension")
        print("[!]")
        import IPython; IPython.embed()
    
    try:
        while True:
            time.sleep(1)
            if status['abort_crash']:
                print("\n[*] Crash found.")
                break
            if status['abort_program']:
                print("\n[*] Fuzzer aborted.")
                break
            if status['abort_tmout']:
                print("\n[*] Timeout reached.")
                break

    except KeyboardInterrupt:
        print("\n[*] Aborting wait. Ctrl-C again for KeyboardInterrupt.")
    except Exception as e:
        print("\n[*] Unknown exception received (%s). Terminating fuzzer." % e)
        status['fuzzer'].stop()
        if drill_extension:
            drill_extension.kill()
        raise

    print("[*] Terminating fuzzer.")
    status['fuzzer'].stop()
    if drill_extension:
        drill_extension.kill()

    if args.tarball:
        print("[*] Dumping results...")
        p = os.path.join("/tmp/", "afl_sync")
        try:
            shutil.rmtree(p)
        except (OSError, IOError):
            pass
        shutil.copytree(status['fuzzer'].work_dir, p)

        tar_name = args.tarball.replace("{}", socket.gethostname())

        tar = tarfile.open("/tmp/afl_sync.tar.gz", "w:gz")
        tar.add(p, arcname=socket.gethostname()+'-'+os.path.basename(args.binary))
        tar.close()
        print("[*] Copying out result tarball to %s" % tar_name)
        shutil.move("/tmp/afl_sync.tar.gz", tar_name)

    os.killpg(os.getpid(), signal.SIGTERM) # send signal to the process group
    

def build_status_str(elapsed_time, first_crash, timeout, afl_cores, fuzzer):
    run_until_str = ""
    timeout_str = ""
    if timeout:
        if first_crash:
            run_until_str = "until first crash or "
        run_until_str += "timeout "
        timeout_str = "for %d of %d seconds " % (elapsed_time, timeout)
    elif first_crash:
        run_until_str = "until first crash "
    else:
        run_until_str = "until stopped by you "

    summary_stats = fuzzer.summary_stats

    return "[*] %.0f fuzzers running %s%scompleted %.0f execs at %.0f execs/sec with %.0f crashes)." % \
           (afl_cores, run_until_str, timeout_str, summary_stats["execs_done"], summary_stats["execs_per_sec"],
            summary_stats["unique_crashes"])


if __name__ == "__main__":
    main()
