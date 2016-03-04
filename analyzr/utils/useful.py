def pprintTable(table, out):
    """Prints out a table of data, padded for alignment
    @param table: The table to print. A list of lists.
    @param out: Output stream (file-like object)
    Each row must have the same number of columns.

    Taken from the comments on this blog post:
    http://ginstrom.com/scribbles/2007/09/04/pretty-printing-a-table-in-python/

    """

    def format(item):
        """Format an item to string"""
        return str(item)

    def get_max_width(table1, index1):
        """Get the maximum width of the given column index"""
        return max([len(format(row1[index1])) for row1 in table1])

    col_paddings = []
    for i in range(len(table[0])):
        col_paddings.append(get_max_width(table, i))

    for row in table:
        # left col
        print(row[0].ljust(col_paddings[0] + 1), end="||", file=out)
        # rest of the cols
        for i in range(1, len(row)):
            col = format(row[i]).rjust(col_paddings[i] + 1)
            print(col, end=" |", file=out)
        print(file=out)
    return