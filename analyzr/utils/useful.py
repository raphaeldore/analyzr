import sys
from io import TextIOWrapper


def pprint_table(table: list,
                 header_labels: list,
                 blank_line_after_header: bool = True,
                 out: TextIOWrapper = sys.stdout):
    """Prints out a table of data, padded for alignment
    @param table: The table to print. A list of lists.
    @param header_labels: A list containing the headers of each columns.
    @param blank_line_after_header: Whether to add a blank line after the header or not.
    @param out: Output stream (file-like object)

    Each row must have the same number of columns.

    Adapted from the code available in the comments of this blog post:
    http://ginstrom.com/scribbles/2007/09/04/pretty-printing-a-table-in-python/

    """

    # We use this often. Why not cache it ;)
    len_nb_elements = len(header_labels)

    def get_max_width(column_index: int):
        """Get the maximum width of the given column index"""
        label_width = len(str(header_labels[column_index]))
        max_column_width = max([len(str(row1[column_index])) for row1 in table])

        # If the label is longer than the largest columns, then the max width is the label
        return label_width if label_width > max_column_width else max_column_width

    col_paddings = []
    for i in range(len_nb_elements):
        col_paddings.append(get_max_width(column_index=i))

    def print_row(row: list):
        for i in range(len_nb_elements):
            col = str(row[i]).rjust(col_paddings[i] + 1)
            print(col, end=" |", file=out)

        # new line
        print(file=out)

    # display header
    print_row(header_labels)

    # display blank line if requested
    if blank_line_after_header:
        print_row([" "] * len_nb_elements)

    for data_row in table:
        print_row(data_row)

    return


if __name__ == "__main__":
    # Temporary tests. Real tests will be added soon.
    header_labels = ["Name this is a long header label", "a", "Fruits"]
    data = [["John", "Carottes", "Pommes"], ["Bob", "Piments", "Fraises"], ["Elvis", "Patates", "Bananes"]]

    pprint_table(table=data, header_labels=header_labels, blank_line_after_header=True, out=sys.stdout)
