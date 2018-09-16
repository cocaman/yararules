rule Threadkit_new_rtf {
    meta:
        author = "James_inthe_box"
        author = "cocaman"
        date = "2018/09"
        maltype = "Threadkit"

    strings:
        $sct = /2e[57]3[46]3[57]4/
        $doc = /2e[46]4[46]f[46]3/
        $exe = /2e[46]5[57]8[46]5/
        $cmd = /2e[46]3[46]d[46]4/

    condition:
	    all of them
}


rule Threadkig_initial_rtf {
    meta:
        author = "James_inthe_box"
        author = "cocaman"
        date = "2018/09"
        maltype = "Threadkit"

    strings:
        $sct = /2e[57]3[46]3[57]4/
        $doc = /2e[46]4[46]f[46]3/
        $exe = /2e[46]5[57]8[46]5/
        $bat = /2e[46]2[46]1[57]4/

    condition:
	     all of them
}
