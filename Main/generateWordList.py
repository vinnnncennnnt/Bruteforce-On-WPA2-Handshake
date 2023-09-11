#!/usr/bin/python3
def dictionary_gen(start, alphabet, max_length, dictionary):    
    if len(start) == max_length:
        return
    for el in alphabet:
        data = start + el
        if len(data) == max_length: 
            dictionary.write(data + '\n')
        dictionary_gen(data, alphabet, max_length, dictionary)

alphabet = 'abcdefghijklmnopqrstuvwxyz'
dictionary = open('dictionary.txt', 'w')

dictionary_gen('aaaa', alphabet, 8, dictionary)