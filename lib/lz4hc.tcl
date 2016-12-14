#--------------------------------------------------------------------------------
#   This is a re-writed source code as Tcl script by kimu_shu.
#   The original source code was written in C language and
#   distributed under following copyright and license:
#--------------------------------------------------------------------------------
#   LZ4 HC - High Compression Mode of LZ4
#   Copyright (C) 2011-2016, Yann Collet.
#
#   BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#   * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following disclaimer
#   in the documentation and/or other materials provided with the
#   distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#   You can contact the author at :
#      - LZ4 source repository : https://github.com/lz4/lz4
#      - LZ4 public forum : https://groups.google.com/forum/#!forum/lz4c
#--------------------------------------------------------------------------------

#--------------------------------------------------------------------------------
# include lz4hc.h
#
set LZ4HC_DEFAULT_CLEVEL 9
set LZ4HC_MAX_CLEVEL 16

set LZ4HC_DICTIONARY_LOGSIZE 16
set LZ4HC_MAXD [ expr (1<<$LZ4HC_DICTIONARY_LOGSIZE) ]
set LZ4HC_MAXD_MASK [ expr ($LZ4HC_MAXD - 1) ]

set LZ4HC_HASH_LOG [ expr ($LZ4HC_DICTIONARY_LOGSIZE-1) ]
set LZ4HC_HASHTABLESIZE [ expr (1 << $LZ4HC_HASH_LOG) ]
set LZ4HC_HASH_MASK [ expr ($LZ4HC_HASHTABLESIZE - 1) ]

#--------------------------------------------------------------------------------
# include lz4.c
#

proc LZ4_read8 { Pptr } {
	global HEAP_IN8
	return $HEAP_IN8($Pptr)
}

proc LZ4_read8o { Pptr ofs } {
	global HEAP_IN8
	return $HEAP_IN8([ expr $Pptr + $ofs ])
}

proc LZ4_read16 { Pptr } {
	# This procedure reads 16-bit data as big-endian
	global HEAP_IN32
	return [ expr $HEAP_IN32($Pptr) >> 16 ]
}

proc LZ4_read32 { Pptr } {
	# This procedure reads 32-bit data as big-endian
	global HEAP_IN32
	return [ expr $HEAP_IN32($Pptr) ]
}

proc LZ4_memmove { Pdest Psrc n } {
	global HEAP_IN32 HEAP_OUT8
	for {} { $n >= 4 } { incr n -4 } {
		set v $HEAP_IN32($Psrc); incr Psrc 4
		set HEAP_OUT8($Pdest) [ expr ($v >> 24) & 0xff ]; incr Pdest
		set HEAP_OUT8($Pdest) [ expr ($v >> 16) & 0xff ]; incr Pdest
		set HEAP_OUT8($Pdest) [ expr ($v >>  8) & 0xff ]; incr Pdest
		set HEAP_OUT8($Pdest) [ expr  $v        & 0xff ]; incr Pdest
	}
	if { $n > 0 } {
		set v $HEAP_IN32($Psrc)
		set HEAP_OUT8($Pdest) [ expr ($v >> 24) & 0xff ]; incr Pdest
		if { $n == 1 } { return {} }
		set HEAP_OUT8($Pdest) [ expr ($v >> 16) & 0xff ]; incr Pdest
		if { $n == 2 } { return {} }
		set HEAP_OUT8($Pdest) [ expr ($v >>  8) & 0xff ]
	}
	return {}
}

proc LZ4_write8 { Pptr val } {
	global HEAP_OUT8
	set HEAP_OUT8($Pptr) [ expr $val & 0xff ]
	return {}
}

proc LZ4_writeLE16 { Pptr val } {
	global HEAP_OUT8
	set HEAP_OUT8($Pptr) [ expr $val & 0xff ]
	incr Pptr
	set HEAP_OUT8($Pptr) [ expr ($val >> 8) & 0xff ]
	return {}
}

proc LZ4_NbCommonBytes { val } {
	if { $val & 0xff000000 } {
		return 0
	} elseif { $val & 0xff0000 } {
		return 1
	} elseif { $val & 0xff00 } {
		return 2
	} else {
		return 3
	}
}

proc LZ4_count { Pin Pmatch PinLimit } {
	set Pstart $Pin
	while { $Pin < ($PinLimit - 3) } {
		set diff [ expr [ LZ4_read32 $Pmatch ] ^ [ LZ4_read32 $Pin ] ]
		if { !$diff } { incr Pin 4; incr Pmatch 4; continue }
		incr Pin [ LZ4_NbCommonBytes $diff ]
		return [ expr $Pin - $Pstart ]
	}

	if { ($Pin < ($PinLimit - 1)) && ( [ LZ4_read16 $Pmatch ] == [ LZ4_read16 $Pin ] ) } {
		incr Pin 2; incr Pmatch 2
	}
	if { ($Pin < $PinLimit) && ( [ LZ4_read8 $Pmatch ] == [ LZ4_read8 $Pin ] ) } {
		incr Pin
	}
	return [ expr $Pin - $Pstart ]
}

#--------------------------------------------------------------------------------
# lz4hc.c
#

proc LZ4HC_hashPtr { Pptr } {
	global HEAP_IN32
	return [ expr (($HEAP_IN32($Pptr) * 2654435761) >> 17) & 32767 ]
}

proc LZ4HC_init_g {} {
	global LZ4HC_HASHTABLESIZE LZ4HC_MAXD
	global LZ4_nextToUpdate LZ4_hashTable LZ4_chainTable

	set LZ4_nextToUpdate 0x10000

	array set LZ4_hashTable [ list ]
	for { set i 0 } { $i < $LZ4HC_HASHTABLESIZE } { incr i } {
		set LZ4_hashTable($i) 0
	}

	array set LZ4_chainTable [ list ]
	for { set i 0 } { $i < $LZ4HC_MAXD } { incr i } {
		set LZ4_chainTable($i) 0xffff
	}
	return {}
}

proc LZ4HC_free_g {} {
	global LZ4_nextToUpdate LZ4_hashTable LZ4_chainTable
	unset LZ4_nextToUpdate
	array unset LZ4_hashTable
	array unset LZ4_chainTable
	return {}
}

proc LZ4HC_Insert_g { Pip } {
	global LZ4_nextToUpdate LZ4_hashTable LZ4_chainTable

	set target [ expr $Pip + 0x10000 ]
	set idx $LZ4_nextToUpdate

	while { $idx < $target } {
		set h [ LZ4HC_hashPtr [ expr $idx - 0x10000 ] ]
		set delta [ expr $idx - $LZ4_hashTable($h) ]
		if { $delta > 0xffff } { set delta 0xffff }
		set LZ4_chainTable([ expr $idx & 0xffff ]) [ expr $delta & 0xffff ]
		set LZ4_hashTable($h) [ expr $idx & 0xffffffff ]
		incr idx
	}

	set LZ4_nextToUpdate $target
	return {}
}

proc LZ4HC_InsertAndFindBestMatch_g { Pip PiLimit RPmatchpos maxNbAttempts } {
	global LZ4_hashTable LZ4_chainTable
	upvar $RPmatchpos Pmatchpos

	if { 0x10000 > $Pip } {
		set lowLimit 0x10000
	} else {
		set lowLimit [ expr $Pip + 1 ]
	}
	set nbAttempts $maxNbAttempts
	set ml 0

	# HC4 match finder
	LZ4HC_Insert_g $Pip
	set matchIndex $LZ4_hashTable([ LZ4HC_hashPtr $Pip ])

	while { ($matchIndex >= $lowLimit) && ($nbAttempts) } {
		incr nbAttempts -1
		if { $matchIndex >= 0x10000 } {
			set Pmatch [ expr $matchIndex - 0x10000 ]
			if { ( [ LZ4_read8o $Pmatch $ml ] == [ LZ4_read8o $Pip $ml ] ) \
				&& ( [ LZ4_read32 $Pmatch ] == [ LZ4_read32 $Pip ] ) } {
				set mlt [ expr [ LZ4_count [ expr $Pip + 4 ] \
					[ expr $Pmatch + 4 ] $PiLimit ] + 4 ]
				if { $mlt > $ml } { set ml $mlt; set Pmatchpos $Pmatch }
			}
		} else {
			set Pmatch [ expr $matchIndex - 0x10000 ]
			if { [ LZ4_read32 $Pmatch ] == [ LZ4_read32 $Pip ] } {
				set PvLimit [ expr $Pip + (0x10000 - $matchIndex) ]
				if { $PvLimit > $PiLimit } { set PvLimit $PiLimit }
				set mlt [ expr [ LZ4_count [ expr $Pip + 4 ] \
					[ expr $Pmatch + 4 ] $PvLimit ] + 4 ]
				if { $mlt > $ml } {
					set ml $mlt
					set Pmatchpos [ expr $matchIndex - 0x10000 ]
				}
			}
		}
		incr matchIndex -$LZ4_chainTable([ expr $matchIndex & 0xffff ])
	}

	return $ml
}

proc LZ4HC_InsertAndGetWiderMatch_g { Pip PiLowLimit PiHighLimit longest \
	RPmatchpos RPstartpos maxNbAttempts } {
	global LZ4_hashTable LZ4_chainTable
	upvar $RPmatchpos Pmatchpos $RPstartpos Pstartpos

	if { 0x10000 > $Pip } {
		set lowLimit 0x10000
	} else {
		set lowLimit [ expr $Pip + 0x10000 ]
	}
	set nbAttempts $maxNbAttempts
	set delta [ expr $Pip - $PiLowLimit ]

	# First Match
	LZ4HC_Insert_g $Pip
	set matchIndex $LZ4_hashTable([ LZ4HC_hashPtr $Pip ])

	while { ($matchIndex >= $lowLimit) && ($nbAttempts) } {
		incr nbAttempts -1
		if { $matchIndex >= 0x10000 } {
			set PmatchPtr [ expr $matchIndex - 0x10000 ]
			if { [ LZ4_read8o $PiLowLimit $longest ] == \
				[ LZ4_read8 [ expr $PmatchPtr - $delta + $longest ] ] } {
				if { [ LZ4_read32 $PmatchPtr ] == [ LZ4_read32 $Pip ] } {
					set mlt [ expr 4 + [ LZ4_count \
						[ expr $Pip + 4 ] \
						[ expr $PmatchPtr + 4 ] $PiHighLimit ] ]
					set back 0

					while { (($Pip + $back) > $PiLowLimit) \
						&& (($PmatchPtr + $back) > 0) \
						&& ( [ LZ4_read8 [ expr $Pip + $back - 1 ] ] == \
							[ LZ4_read8 [ expr $PmatchPtr + $back - 1 ] ] ) } {
						incr back -1
					}

					set mlt [ expr $mlt - $back ]

					if { $mlt > $longest } {
						set longest $mlt
						set Pmatchpos [ expr $PmatchPtr + $back ]
						set Pstartpos [ expr $Pip + $back ]
					}
				}
			}
		} else {
			set PmatchPtr [ expr $matchIndex - 0x10000 ]
			if { [ LZ4_read32 $PmatchPtr ] == [ LZ4_read32 $Pip ] } {
				set back 0
				set PvLimit [ expr $Pip + 0x10000 - $matchIndex ]
				if { $PvLimit > $PiHighLimit } { set PvLimit $PiHighLimit }
				set mlt [ expr [ LZ4_count [ expr $Pip + 4 ] \
					[ expr $PmatchPtr + 4 ] $PvLimit ] + 4 ]
				if { (($Pip + $mlt) == $PvLimit) && ($PvLimit < $PiHighLimit) } {
					incr mlt [ LZ4_count [ expr $Pip + $mlt ] 0 $PiHighLimit ]
				}
				while { (($Pip + $back) > $PiLowLimit) \
					&& (($matchIndex + $back) > $lowLimit) \
					&& ( [ LZ4_read8 [ expr $Pip + $back - 1 ] ] == \
						[ LZ4_read8 [ expr $PmatchPtr + $back - 1 ] ] ) } {
					incr back -1
				}
				set mlt [ expr $mlt - $back ]
				if { $mlt > $longest } {
					set longest $mlt
					set Pmatchpos [ expr $matchIndex - 0x10000 + $back ]
					set Pstartpos [ expr $Pip + $back ]
				}
			}
		}
		incr matchIndex -$LZ4_chainTable([ expr $matchIndex & 0xffff ])
	}

	return $longest
}

proc LZ4HC_encodeSequence_nl { RPip RPop RPanchor matchLength Pmatch } {
	upvar $RPip Pip $RPop Pop $RPanchor Panchor

	# puts "literal : [ expr $Pip - $Panchor \
		]  --  match : $matchLength  --  offset : [ expr $Pip - $Pmatch ]"

	# Encode Literal Length
	set length [ expr $Pip - $Panchor ]
	set Ptoken $Pop; incr Pop
	if { $length >= 15 } {
		set token 0xf0
		set len [ expr $length - 15 ]
		for {} { $len > 254 } { incr len -255 } {
			LZ4_write8 $Pop 255; incr Pop
		}
		LZ4_write8 $Pop $len; incr Pop
	} else {
		set token [ expr $length << 4 ]
	}

	# Copy Literals
	LZ4_memmove $Pop $Panchor $length
	incr Pop $length

	# Encode Offset
	LZ4_writeLE16 $Pop [ expr $Pip - $Pmatch ]; incr Pop 2

	# Encode MatchLength
	set length [ expr $matchLength - 4 ]
	if { $length >= 15 } {
		LZ4_write8 $Ptoken [ expr $token + 15 ]
		incr length -15
		for {} { $length > 509 } { incr length -510 } {
			LZ4_write8 $Pop 255; incr Pop
			LZ4_write8 $Pop 255; incr Pop
		}
		if { $length > 254 } {
			incr length -255
			LZ4_write8 $Pop 255; incr Pop
		}
		LZ4_write8 $Pop $length; incr Pop
	} else {
		LZ4_write8 $Ptoken [ expr $token + $length ]
	}

	# Prepare next loop
	incr Pip $matchLength
	set Panchor $Pip

	return 0
}

proc LZ4HC_compress_generic_g_nl { inputSize compressionLevel } {
	global LZ4HC_MAX_CLEVEL LZ4HC_DEFAULT_CLEVEL

	set Pip 0
	set Panchor $Pip
	set Piend [ expr $Pip + $inputSize ]
	set Pmflimit [ expr $Piend - 12 ]
	set Pmatchlimit [ expr $Piend - 5 ]

	set Pop 0

	set maxNbAttempts {}
	set ml {}; set ml2 {}; set ml3 {}; set ml0 {}
	set Pref 0
	set Pstart2 0
	set Pref2 0
	set Pstart3 0
	set Pref3 0
	set Pstart0 {}
	set Pref0 {}

	# Init
	if { $compressionLevel > $LZ4HC_MAX_CLEVEL } { set compressionLevel $LZ4HC_MAX_CLEVEL }
	if { $compressionLevel < 1 } { set compressionLevel $LZ4HC_DEFAULT_CLEVEL }
	set maxNbAttempts [ expr 1 << ($compressionLevel - 1) ]

	incr Pip

	# Main Loop
	while { $Pip < $Pmflimit } {
		set ml [ LZ4HC_InsertAndFindBestMatch_g $Pip $Pmatchlimit Pref $maxNbAttempts ]
		if { !$ml } { incr Pip; continue }

		# saved, in case we would skip too much
		set Pstart0 $Pip
		set Pref0 $Pref
		set ml0 $ml

		set cont_s2 1
		# _Search2:
		while { $cont_s2 } {
			if { ($Pip + $ml) < $Pmflimit } {
				set ml2 [ LZ4HC_InsertAndGetWiderMatch_g [ expr $Pip + $ml - 2 ] \
					[ expr $Pip + 0 ] $Pmatchlimit $ml Pref2 Pstart2 $maxNbAttempts ]
			} else {
				set ml2 $ml
			}
			if { $ml2 == $ml } {
				# No better match
				if { [ LZ4HC_encodeSequence_nl Pip Pop Panchor $ml $Pref ] } {
					return 0
				}
				# continue;
				set cont_s2 0
				continue
			}
			if { $Pstart0 < $Pip } {
				if { $Pstart2 < ($Pip + $ml0) } {
					# empirical
					set Pip $Pstart0
					set Pref $Pref0
					set ml $ml0
				}
			}

			# Here, start0==ip
			if { ($Pstart2 - $Pip) < 3 } {
				# First match too small : removed
				set ml $ml2
				set Pip $Pstart2
				set Pref $Pref2
				# goto _Search2;
				continue
			}

			set cont_s3 1
			# _Search3:
			while { $cont_s3 } {
				# Currently we have :
				# ml2 > ml1, and
				# ip1+3 <= ip2 (usually < ip1+ml1)
				if { ($Pstart2 - $Pip) < 18 } {
					set new_ml $ml
					if { $new_ml > 18 } { set new_ml 18 }
					if { ($Pip + $new_ml) > ($Pstart2 + $ml2 + 4) } {
						set new_ml [ expr ($Pstart2 - $Pip) + $ml2 - 4 ]
					}
					set correction [ expr $new_ml - ($Pstart2 - $Pip) ]
					if { $correction > 0 } {
						incr Pstart2 $correction
						incr Pref2 $correction
						incr ml2 -$correction
					}
				}
				# Now, we have start2 = ip+new_ml, with new_ml = min(ml, OPTIMAL_ML=18)
				#
				if { ($Pstart2 + $ml2) < $Pmflimit } {
					set ml3 [ LZ4HC_InsertAndGetWiderMatch_g [ expr $Pstart2 + $ml2 - 3 ] \
						$Pstart2 $Pmatchlimit $ml2 Pref3 Pstart3 $maxNbAttempts ]
				} else {
					set ml3 $ml2
				}
				if { $ml3 == $ml2 } {
					# No better match : 2 sequences to encode
					# ip & ref are known; Now for ml
					if { $Pstart2 < ($Pip + $ml) } { set ml [ expr $Pstart2 - $Pip ] }
					# Now, encode 2 sequences
					if { [ LZ4HC_encodeSequence_nl Pip Pop Panchor $ml $Pref ] } {
						return 0
					}
					set Pip $Pstart2
					if { [ LZ4HC_encodeSequence_nl Pip Pop Panchor $ml2 $Pref2 ] } {
						return 0
					}
					# continue;
					set cont_s3 0
					set cont_s2 0
					continue
				}
				if { $Pstart3 < ($Pip + $ml + 3) } {
					# Not enough space for match 2 : remove it
					if { $Pstart3 >= ($Pip + $ml) } {
						# can write Seq1 immediately ==> Seq2 is removed, so Seq3 becomes Seq1
						if { $Pstart2 < ($Pip + $ml) } {
							set correction [ expr $Pip + $ml - $Pstart2 ]
							incr Pstart2 $correction
							incr Pref2 $correction
							incr ml2 -$correction
							if { $ml2 < 4 } {
								set Pstart2 $Pstart3
								set Pref2 $Pref3
								set ml2 $ml3
							}
						}

						if { [ LZ4HC_encodeSequence_nl Pip Pop Panchor $ml $Pref ] } {
							return 0
						}
						set Pip $Pstart3
						set Pref $Pref3
						set ml $ml3

						set Pstart0 $Pstart2
						set Pref0 $Pref2
						set ml0 $ml2
						# goto _Search2;
						set cont_s3 0
						continue
					}

					set Pstart2 $Pstart3
					set Pref2 $Pref3
					set ml2 $ml3
					# goto _Search3;
					continue
				}

				# OK, now we have 3 ascending matches; let's write at least the first one
				# ip & ref are known; Now for ml
				if { $Pstart2 < ($Pip + $ml) } {
					if { ($Pstart2 - $Pip) < 15 } {
						if { $ml > 18 } { set ml 18 }
						if { ($Pip + $ml) > ($Pstart2 + $ml2 - 4) } {
							set ml [ expr ($Pstart2 - $Pip) + $ml2 - 4 ]
						}
						set correction [ expr $ml - ($Pstart2 - $Pip) ]
						if { $correction > 0 } {
							incr Pstart2 $correction
							incr Pref2 $correction
							incr ml2 -$correction
						}
					} else {
						set ml [ expr $Pstart2 - $Pip ]
					}
				}
				if { [ LZ4HC_encodeSequence_nl Pip Pop Panchor $ml $Pref ] } {
					return 0
				}

				set Pip $Pstart2
				set Pref $Pref2
				set ml $ml2

				set Pstart2 $Pstart3
				set Pref2 $Pref3
				set ml2 $ml3

				# goto _Search3
				continue
			}
			# ^while { $cont_s3 }
		}
		# ^while { $cont_s2 }
	}
	# ^while { $Pip < $Pmflimit }

	# Encode Last Literals
	set lastRun [ expr $Piend - $Panchor ]
	if { $lastRun >= 15 } {
		LZ4_write8 $Pop [ expr 15 << 4 ]; incr Pop
		incr lastRun -15
		for {} { $lastRun > 254 } { incr lastRun -255 } {
			LZ4_write8 $Pop 255; incr Pop
		}
		LZ4_write8 $Pop $lastRun; incr Pop
	} else {
		LZ4_write8 $Pop [ expr $lastRun << 4 ]; incr Pop
	}
	LZ4_memmove $Pop $Panchor [ expr $Piend - $Panchor ]
	incr Pop [ expr $Piend - $Panchor ]

	# End
	return $Pop
}

proc LZ4_compress { src { compressionLevel 0 } } {
	global HEAP_IN8 HEAP_IN32 HEAP_OUT8
	set srcSize [ string length $src ]

	# Allocate input heap
	array set HEAP_IN8 [ list ]
	array set HEAP_IN32 [ list ]
	binary scan "$src\0\0\0" H* srcHex
	for { set i 0 } { $i < $srcSize } { incr i } {
		set HEAP_IN8($i) [ expr 0x[ string range $srcHex [ expr $i * 2 ] [ expr $i * 2 + 1 ] ] ]
		set HEAP_IN32($i) [ expr 0x[ string range $srcHex [ expr $i * 2 ] [ expr $i * 2 + 7 ] ] ]
	}

	# Allocate output heap
	array set HEAP_OUT8 [ list ]

	# Initialize context
	LZ4HC_init_g

	# Execute compression
	set len [ LZ4HC_compress_generic_g_nl $srcSize $compressionLevel ]

	# Cleanup context
	LZ4HC_free_g

	# Receive result
	set result {}
	set BLKSZ 1024
	for { set i 0 } { $i < $len } { incr i $BLKSZ } {
		set tmp {}
		for { set j $i } { ($j < $len) && ($j < ($i + $BLKSZ)) } { incr j } {
			set tmp "$tmp[ binary format c $HEAP_OUT8($j) ]"
		}
		set result "$result$tmp"
	}

	# Release heap
	unset HEAP_IN32
	unset HEAP_OUT8

	return $result
}

