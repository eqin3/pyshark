import os
import atexit
import asyncio
import sys
# from distutils.version import LooseVersion
from packaging import version
import subprocess
import time
import hashlib, uuid

from pyshark.capture.capture import Capture
from pyshark.capture.file_capture import FileCapture
from pyshark.tshark.tshark import get_tshark_interfaces, get_process_path


class BgCapture(Capture):
    """Represents a live capture on a network interface."""

    def __init__(self, interface=None, remote_host=None, remote_port=2002, bpf_filter=None, display_filter=None, only_summaries=False,
                 decryption_key=None, encryption_type='wpa-pwk', output_file=None, decode_as=None,
                 disable_protocol=None, tshark_path=None, override_prefs=None, capture_filter=None,
                 monitor_mode=False, use_json=False, include_raw=False, eventloop=None, custom_parameters=None,
                 debug=False):
        """Creates a new live capturer on a given interface. Does not start the actual capture itself.

        :param interface: Name of the interface to sniff on or a list of names (str). If not given, runs on all interfaces.
        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information
        :param decryption_key: Optional key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or
        'WPA-PWK'. Defaults to WPA-PWK).
        :param output_file: Additionally save live captured packets to this file.
        :param decode_as: A dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell tshark
        to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
        it attempt to decode any port 8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: A dictionary of tshark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}.
        :param capture_filter: Capture (wireshark) filter to use.
        :param disable_protocol: Tells tshark to remove a dissector for a specifc protocol.
        :param use_json: Uses tshark in JSON mode (EXPERIMENTAL). It is a good deal faster than XML
        but also has less information. Available from Wireshark 2.2.0.
        :param custom_parameters: A dict of custom parameters to pass to tshark, i.e. {"--param": "value"}
        """

        super(BgCapture, self).__init__(display_filter=display_filter, only_summaries=only_summaries,
                                          decryption_key=decryption_key, encryption_type=encryption_type,
                                          output_file=output_file, decode_as=decode_as, disable_protocol=disable_protocol,
                                          tshark_path=tshark_path, override_prefs=override_prefs,
                                          capture_filter=capture_filter, use_json=use_json, include_raw=include_raw,
                                          eventloop=eventloop, custom_parameters=custom_parameters,
                                          debug=debug)
        self.bpf_filter = bpf_filter
        self.monitor_mode = monitor_mode
        # self._output_file = '/root/pys.pcap'
        self._output_file = "/var/tmp/tshark_"+hashlib.md5(str(uuid.uuid4()).encode('utf-8')).hexdigest()+".pcap"

        if sys.platform == "win32" and monitor_mode:
            raise WindowsError("Monitor mode is not supported by the Windows platform")

        if interface is None:
            self.interfaces = get_tshark_interfaces(tshark_path)
        else:
            self.interfaces = interface

        if remote_host:
            self.interfaces = 'rpcap://%s:%d/%s' % (remote_host, remote_port, interface)

    def _get_dumpcap_parameters(self):
        # Don't report packet counts.
        params = ["-q"]
        params = []
        if self._get_tshark_version() < version.parse("2.5.0"):
            # Tshark versions older than 2.5 don't support pcapng. This flag forces dumpcap to output pcap.
            params += ["-P"]
        if self.bpf_filter:
            params += ["-f", self.bpf_filter]
        if self.monitor_mode:
            params += ["-I"]
        if self.interfaces:
            params += ["-i", self.interfaces]
        return params

    # Backwards compatibility
    sniff = Capture.load_packets

    async def packets_from_tshark(self, packet_callback, packet_count=None, close_tshark=True):
        """
        A coroutine which creates a tshark process, runs the given callback on each packet that is received from it and
        closes the process when it is done.

        Do not use interactively. Can be used in order to insert packets into your own eventloop.
        """
        tshark_process = await self._get_tshark_process(packet_count=packet_count)
        self._tshark_process = tshark_process

    def close(self):
        self.eventloop.run_until_complete(self._cleanup_subprocess(self._tshark_process))



    def load_packets(self):
        self.close()
        pcap = FileCapture(self._output_file)

        def _del_output_file():
            if os.path.isfile(self._output_file):
                os.remove(self._output_file)
        atexit.register(_del_output_file)

        return pcap

    async def _get_tshark_process(self, packet_count=None, stdin=None):
        """Returns a new tshark process with previously-set parameters."""
        parameters = [self._get_tshark_path(), "-l"] + self._get_dumpcap_parameters() + self.get_parameters()
        self._log.debug("Creating TShark subprocess with parameters: " + " ".join(parameters))
        self._log.debug("Executable: %s" % parameters[0])
        tshark_process = await asyncio.create_subprocess_exec(*parameters,
                                                              stdout=subprocess.PIPE,
                                                              stderr=subprocess.PIPE,
                                                              stdin=stdin)
        self._created_new_process(parameters, tshark_process)
        return tshark_process