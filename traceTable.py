"""
run:
python -m trace --trace tamrin.py

"""


import sys

if len(sys.argv) < 2:
    print("Usage: python traceTable.py program.py")
    exit()

file_name = sys.argv[1]
past_locals = {}
variable_list = []
table_content = ""
ignored_variables = set([
    'file_name', 'trace', 'sys', 'past_locals', 'variable_list',
    'table_content', 'getattr', 'name', 'self', 'object', 'consumed',
    'data', 'ignored_variables'
])

def trace(frame, event, arg_unused):
    global past_locals, variable_list, table_content, ignored_variables
    relevant_locals = {}
    all_locals = frame.f_locals.copy()
    for k, v in all_locals.items():
        if not k.startswith("__") and k not in ignored_variables:
            relevant_locals[k] = v
    if len(relevant_locals) > 0 and past_locals != relevant_locals:
        for i in relevant_locals:
            if i not in past_locals:
                variable_list.append(i)
        table_content += str(frame.f_lineno) + " || "
        for variable in variable_list:
            table_content += str(relevant_locals.get(variable, "")) + " | "
        table_content = table_content[:-2]
        table_content += '\n'
        past_locals = relevant_locals.copy()
    return trace

sys.settrace(trace)
with open(file_name) as f:
    code = compile(f.read(), file_name, 'exec')
    exec(code)

table_header = "L || "
for variable in variable_list:
    table_header += variable + ' | '
table_header = table_header[:-2]
print(table_header)
print(table_content)
