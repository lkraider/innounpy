class StructParser(object):
    """Simple dumb parser to read version relevant info from Inno Setup Struct.pas files"""

    def __init__(self, filename='Struct.pas'):
        self.filename = filename
        self._vars = {}
        self._data = None

    @property
    def raw_data(self):
        if not self._data:
            f = open(self.filename)
            self._data = f.read()
            f.close()
        return self._data

    def _parse(self):
        """Collect all relevant variables from file"""

        self._vars['TSetupID'] = self._find_data('SetupID: TSetupID = \'', '\'')
        self._vars['SetupHeaderStrings'] = int(self._find_data('SetupHeaderStrings = ', ';'))

        TSetupHeader = self._find_data('TSetupHeader = packed record', ':')
        self._vars['TSetupHeader_Strings'] = [string.strip() for string in TSetupHeader.split(',')]

        self._data = None

    def _find_data(self, match, end_match):
        start = self.raw_data.index(match) + len(match)
        return self.raw_data[start:self.raw_data.find(end_match, start)].strip()

    def __getattr__(self, key):
        """Try to get key from dictionary parsing the file if necessary"""
        try:
            value = self._vars[key]
            if value == KeyError:
                self.__getattribute__(key)
        except KeyError:
            self._parse()
            try:
                value = self._vars[key]
            except KeyError:
                self._vars[key] = KeyError
                self.__getattribute__(key)
        return value

    # Iterate as the underlying dictionary
    def keys(self):
        if not self._vars:
            self._parse()
        return self._vars.keys()

    def __getitem__(self, key):
        if not self._vars:
            self._parse()
        return self._vars.__getitem__(key)

    def __iter__(self):
        if not self._vars:
            self._parse()
        return self._vars.__iter__()


def parser_for_version(version):
    import os
    major, minor, release = map(int, version.split('.'))
    filepath = 'structs/Struct%d%d%02d.pas' % (major, minor, release)
    if not os.path.isfile(filepath):
        raise IOError('File not found: %s' % filepath)
    return StructParser(filepath)


if __name__ == '__main__':
    from pprint import pprint
    parser = parser_for_version('5.2.3')
    pprint(dict(parser))
