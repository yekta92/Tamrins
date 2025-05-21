from pprint import pprint 

d={
    "a.x.q":10,
    "a.x.w":10,
    "a.x.e":10,
    "a":{"x":{"s":10}},
    "a":{"m":10},
    "a.y":10,
    "a.z":10,
    "b.x":10,
    "b.y":10,
    "c":10,
    "d":10
}




def deep_merge(d1,d2):
    md={**d1,**d2}
    for k in set(d1).intersection(d2):
        if d1[k] != d2[k]:
            assert type(d1[k]) is dict
            assert type(d2[k]) is dict
            md[k]=deep_merge(d1[k],d2[k])
    return md            


def extract(d):
    new_d={}
    candidate=set()
    
    for k in d.keys():
        if "." in k:
            index_dot=k.find(".")
            left=k[: index_dot]
            candidate.add(left)
        else:
            new_d[k]=d[k]  
            
    for c in candidate:
        if c=="a":
            pass
        candidate_d={}
        for k in d.keys():
            if k.startswith(c+"."):
                index_dot=k.find(".")
                right=k[index_dot + 1 :]
                candidate_d[right]=d[k]

        if c in new_d:
            a=new_d[c]
            b=extract(candidate_d)
            new_d[c]=deep_merge(a,b)
        else:
            new_d[c]=extract(candidate_d)
        pass
    return new_d




pprint(extract(d))