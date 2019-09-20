def u_law_d(i8bit):
    i8bit &= 0xff  # marginalising data larger than byte
    i8bit ^= 0xff  # flipping back bytes
    sign = False

    if i8bit & 0x80 == 0x80:  # if it is signed negative 1000 0000
        sign = True  # bool option since sign is not really used
        i8bit &= 0x7f  # removing the sign of value

    pos = ((i8bit & 0xf0) >> 4) + 5  # grabing initial value for mantisa

    # generating decoded data
    decoded = i8bit & 0xf  # grabing 1st nibble from 8 bit integer
    decoded <<= pos - 4  # shifting by position -4 aka generating mantisa for 16 bit integer
    decoded |= 1 << (pos - 5)  # OR gate for specific bit
    decoded |= 1 << pos  # OR gate for another specific bit
    decoded -= 0x21  # removing the 10 0001 from value to generate exact value

    if not sign:
        return decoded  # if positive number will be returned as is
    else:
        return -decoded  # if negative the number will be returned inverted