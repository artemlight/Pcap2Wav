# Pythonic SDP/SDPPLIN Parser
# SDP = Session Description Protocol
#
# Copyright (C) 2008 David Bern
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import base64

def _parse_sdpplin_line(item):
    """ Returns a (name,value) tuple when given an Sdpplin attribute
    e.g. AvgPacketSize:integer;744 => (AvgPacketSize,744)
    """
    name = item.split(':')[0]
    value = item[len(name)+ 1:]
    if value.find(';') != -1:
        #type = value.split(';')[0]
        #value = value[len(type) + 1:]
        type, sep, value = value.partition(';')
        if type == 'integer':
            value = int(value)
        if type == 'buffer':
            value = base64.b64decode(value[1:-1])
        if type == 'string':
            value = value[1:-1]
    return name, value

class SDPMediaDesc:
    """ Holds the (a)ttribute and (b)andwidth values for an SDP Media Desc """
    def __init__(self,value):
        #   m=<media> <port> <transport> <fmt list>
        self.media, self.port, self.transport, self.fmt_list = value.split(' ',3)
        self.a = []
        self.b = []
        self.port = int(self.port)
        #self.media = ''
        #self.port = 0
        #self.transport = ''
        #self.fmt_list = []

class SDPParser:
    def __init__(self, data = None):
        """ Parses a full SDP data string.
        Alternatively, send lines to the parseLine method. """
        self.v = []
        self.o = []
        self.s = []
        self.i = []
        self.t = []
        self.a = []
        self.media_descriptions = {}

        self.last_desc = None

        # Variables are provided for convenience
        self.protocol_version = None
        self.session_name = None
        self.session_desc = None
        self.start_time = None
        self.stop_time = None


        if data is None:
            return
        lines = [ l for l in data.split('\r\n') if l ]
        for line in lines:
            self.parseLine(line)


    def parseLine(self, line):
        """ Parses an SDP line. SDP protocol requires lines be parsed in order
        as the m= attribute tells the parser that the following a= values
        describe the last m= """
        type = line[0]
        value = line[2:].strip()
        if type == 'v':
            self.v.append(value)
            self.protocol_version = value
        elif type == 'o':
            self.o.append(value)
        elif type == 's': # Session Name
            self.s.append(value)
            self.session_name = value
        elif type == 'i': # Session Description
            self.i.append(value)
            self.session_desc = value
        elif type == 'c': # Session Description
            pass
        elif type =='t': # Time
            try:
                start_time, stop_time = ['t' for t in value.split(' ')]
            except ValueError:
                pass
        elif type == 'a':
            if self.last_desc is None:
                # Appends to the session attributes
                self.a.append(value)
            else:
                # or to the media description attributes
                self.last_desc.a.append(value)
        elif type == 'm':
            self.last_desc = SDPMediaDesc(value)
            self.media_descriptions[self.last_desc.media] = self.last_desc
        elif type == 'b':
            self.last_desc.b.append(value)
        else:
            # Need to add email and phone
            raise TypeError('Unknown type: %s' % type)

