import argparse


def strictly_positive_int(value: any) -> int:
    """
    Custom argparse type for a strictly positive integer value.
    
    :param value: argument value to check
    :return: argument as integer if it is strictly positive
    :raises argparse.ArgumentTypeError: if argument does not represent a strictly positive integer
    """
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} does not represent an integer.")
    else:
        if ivalue < 1:
            raise argparse.ArgumentTypeError(f"{value} does not represent a strictly positive integer.")
        return ivalue
