MUTATION_PATTERN =      ["push", "not", "sub", "pop", "sub"]
LEA_PATTERN =           ["lea", "pushf", "sub", "popf"]
IMMEDIATE_MOV_PATTERN = ["pushf", "not", "add", "xor", "rol", "popf", 
                         "pushf", "not", "add", "xor", "rol", "popf"]