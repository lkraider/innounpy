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
        TSetupHeader_StringsList = self._find_data('TSetupHeader = packed record', ':')
        self._vars['TSetupHeader_StringsList'] = [string.strip() for string in TSetupHeader_StringsList.split(',')]
        assert(len(self.TSetupHeader_StringsList) == self.SetupHeaderStrings)

        TSetupHeader_IntegersList = self._find_data('NumLanguageEntries, ', ':', keep_start=True)
        self._vars['TSetupHeader_IntegersList'] = [integer.strip() for integer in TSetupHeader_IntegersList.split(',')]

        TSetupHeaderOption = self._find_data('TSetupHeaderOption = (', ')')
        self._vars['TSetupHeaderOption'] = [option.strip() for option in TSetupHeaderOption.split(',')]

        self._vars['SetupLanguageEntryStrings'] = int(self._find_data('SetupLanguageEntryStrings = ', ';'))
        TSetupLanguageEntry_StringsList = self._find_data('Name, LanguageName, ', ':', keep_start=True)
        self._vars['TSetupLanguageEntry_StringsList'] = [string.strip() for string in TSetupLanguageEntry_StringsList.split(',')]
        assert(len(self.TSetupLanguageEntry_StringsList) == self.SetupLanguageEntryStrings)

        self._vars['SetupCustomMessageEntryStrings'] = int(self._find_data('SetupCustomMessageEntryStrings = ', ';'))
        TSetupCustomMessageEntry_StringsList = self._find_data('TSetupCustomMessageEntry = packed record', ':')
        self._vars['TSetupCustomMessageEntry_StringsList'] = [string.strip() for string in TSetupCustomMessageEntry_StringsList.split(',')]
        assert(len(self.TSetupCustomMessageEntry_StringsList) == self.SetupCustomMessageEntryStrings)

        self._data = None

    def _find_data(self, match, end_match, keep_start=False):
        start = self.raw_data.index(match)
        if not keep_start:
            start += len(match)
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
    major, minor, release = map(int, version.replace('u', '').split('.'))
    is_unicode = 'u' if version[-1] == 'u' else ''
    filepath = 'structs/Struct%d%d%02d%s.pas' % (major, minor, release, is_unicode)
    if not os.path.isfile(filepath):
        raise IOError('File not found: %s' % filepath)
    return StructParser(filepath)


if __name__ == '__main__':
    from pprint import pprint
    parser = parser_for_version('5.2.3')
    pprint(dict(parser))
