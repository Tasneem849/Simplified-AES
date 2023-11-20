#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t byte;        //unsigned 8-bit integer.

typedef uint16_t twobytes;   //unsigned 16-bit integer.

static twobytes RCON[2] = {0x80, 0x30};

static twobytes subKeys[3];

static twobytes S_Box[] = { 9,  4, 10, 11,
                           13,  1,  8,  5,
                            6,  2,  0,  3,
                           12, 14, 15,  7, };


static twobytes inverseS_Box[] = { 10,  5,  9, 11,
                                    1,  7,  8, 15,
                                    6,  0,  2,  3,
                                   12,  4, 13, 14, };


byte mix(byte x)
{
    byte x0 = (x & 0xF0) >> 4;
    byte x1 = (x & 0x0F);

    byte temp1 = x0;
    byte temp2 = x1;

    byte x00, x11;

    for(int i = 0; i <= 1; i++)
    {
        if((temp1 & 0x8) == 0x8)
        {
            temp1 = (temp1 << 1) & 0x0F;
            temp1 = temp1 ^ 0x03;
        }

        else
        {
           temp1 = (temp1 << 1) & 0x0F;
        }
    }

    for(int k = 0; k <= 1; k++)
    {
        if((temp2 & 0x08) == 0x08)
        {
            temp2 = (temp2 << 1) & 0x0F;
            temp2 = temp2 ^ 0x03;
        }

        else
            temp2 = (temp2 << 1) & 0x0F;
    }

    x00 = temp2 ^ x0;
    x11 = temp1 ^ x1;

    return (x00 << 4) | (x11 & 0x0F);
}

byte inverse_mix(byte x)
{
    byte x0 = (x & 0xF0) >> 4;
    byte x1 = (x & 0x0F);

    byte S[2];

    byte X[2];

    X[0] = x0;
    X[1] = x1;

    S[0] = x0;
    S[1] = x1;

    byte nine[2];
    byte two[2];

    byte x00, x11;

    for(int j = 0; j <=1; j++)
    {
        for(int i = 0; i <= 2; i++)
        {
            if((S[j] & 0x8) == 0x8)
            {
                S[j] = (S[j] << 1) & 0x0F;
                S[j] = S[j] ^ 0x03;
            }

            else
            {
               S[j] = (S[j] << 1) & 0x0F;
            }
        }

        nine[j] = S[j] ^ X[j];
    }

    S[0] = x0;
    S[1] = x1;

    for(int j = 0; j <=1; j++)
    {
        for(int i = 0; i < 1; i++)
        {
            if((S[j] & 0x8) == 0x8)
            {
                S[j] = (S[j] << 1) & 0x0F;
                S[j] = S[j] ^ 0x03;
            }

            else
            {
               S[j] = (S[j] << 1) & 0x0F;
            }
        }

        two[j] = S[j];
    }

    x00 = nine[0] ^ two[1];
    x11 = two[0]  ^ nine[1];

    return (x00 << 4) | (x11 & 0x0F);
}


byte RotNib(byte x)
{
    return (((x & 0x0F) << 4) | ((x & 0xF0) >> 4));
}

twobytes SubNib(twobytes x)
{
    return S_Box[(x & 0xF000)>>12] << 12 | S_Box[(x & 0x0F00)>>8] << 8 | S_Box[(x & 0x00F0)>>4] << 4 | S_Box[(x & 0x000F)];
}


twobytes inverse_SubNib(twobytes x)
{
    return inverseS_Box[(x & 0xF000)>>12] << 12 | inverseS_Box[(x & 0x0F00)>>8] << 8 | inverseS_Box[(x & 0x00F0)>>4] << 4 | inverseS_Box[(x & 0x000F)];
}


void keyExpansion(twobytes key)
{
    byte keyWords[6] = { 0 };

    keyWords[0] = (key & 0xFF00) >> 8;       //W0
    keyWords[1] = (key & 0x00FF);            //W1

    for(int i = 0; i <= 3; i++)              //W2 --> W5
    {
        if(i%2 == 0)
            keyWords[i + 2] = keyWords[i] ^ RCON[i/2] ^ SubNib(RotNib(keyWords[i + 1]));
        else
            keyWords[i + 2] = keyWords[i] ^ keyWords[i + 1];
    }

    for (int j = 0; j <= 2; j++)
        subKeys[j] = (keyWords[j*2] << 8 & 0xFF00) | (keyWords[j*2 + 1] & 0x00FF);
}

twobytes shiftRow(twobytes x)
{
    return (x & 0xF000) | (x & 0x000F) << 8 | (x & 0x00F0) | (x & 0x0F00) >> 8;
}


//K0 = w0 + w1          w0 is  half left   and   w1 is half right
//K1 = w2 + w3          w2 = w0 ^ g(w1)         w3 = w1 ^ w2
//K2 = w4 + w5          w4 = w2 ^ g(w3)         w5 = w3 ^ w4
//g(w) = RC ^ SubNib(RotNib(w))


//-------------Encryption Function-------------//

twobytes ENC(twobytes key, twobytes plaintext)
{
    twobytes result;

    keyExpansion(key);

    result = plaintext ^ subKeys[0];

    result = shiftRow(SubNib(result));

    byte s1 = mix((result & 0xFF00) >> 8);

    byte s2 = mix(result & 0x00FF);

    result = (s1 << 8 & 0xFF00) | (s2 << 8 & 0xFF00) >> 8;

    result = result ^ subKeys[1];

    result = shiftRow(SubNib(result));

    result = result ^ subKeys[2];

    printf("The ciphertext is %X\n", result);

    return result;
}

//-------------Decryption Function-------------//

twobytes DEC(twobytes key, twobytes ciphertext)
{
    twobytes result;

    keyExpansion(key);

    result = ciphertext ^ subKeys[2];

    result = shiftRow(inverse_SubNib(result));

    result = result ^ subKeys[1];

    byte s1 = inverse_mix((result & 0xFF00) >> 8);

    byte s2 = inverse_mix(result & 0x00FF);

    result = (s1 << 8 & 0xFF00) | (s2 << 8 & 0xFF00) >> 8;

    result = shiftRow(inverse_SubNib(result));

    result = result ^ subKeys[0];

    printf("The plaintext is %X\n", result);

    return result;
}


int main(int argc, const char *argv[])
{
    if (argc != 4)
    {
        printf("Needs 3 parameters. Expects:\n\t%s  ENC|DEC  key  data\n", argv[0]);
        exit(1);
    }

    twobytes x = strtol(argv[2], NULL, 16);
    twobytes y = strtol(argv[3], NULL, 16);

    if (strcmp(argv[1], "ENC") == 0)
        return ENC(x, y);

    if (strcmp(argv[1], "DEC") == 0)
        return DEC(x, y);

    else
        printf("Invalid Input.\n");

    return 0;
}
