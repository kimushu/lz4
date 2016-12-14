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
# Standard library
#
proc memcpy { Pdest Psrc n } {
	global HEAP
	if { $n > 0 } {
		set dofs [ expr $Pdest * 2 ]
		set sofs [ expr $Psrc * 2 ]
		set n2 [ expr $n * 2 - 1 ]
		set HEAP [ string replace $HEAP $dofs [ expr $dofs + $n2 ] \
			[ string range $HEAP $sofs [ expr $sofs + $n2 ] ] ]
	}
	return $Pdest
}

proc init_heap { size } {
	global HEAP
	set HEAP [ string repeat zz $size ]
	return {}
}

proc str2heap { Pdest src } {
	global HEAP
	set dofs [ expr $Pdest * 2 ]
	binary scan $src H* hex
	set n2 [ expr [ string length $src ] * 2 - 1 ]
	set HEAP [ string replace $HEAP $dofs [ expr $dofs + $n2 ] $hex ]
	return {}
}

proc heap2str { Psrc n } {
	global HEAP
	set sofs [ expr $Psrc * 2 ]
	set n2 [ expr $n * 2 - 1 ]
	set hex [ string range $HEAP $sofs [ expr $sofs + $n2 ] ]
	return [ binary format H* $hex ]
}

# set LZ4HC_HEAPMODE 0

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
set MINMATCH 4

set WILDCOPYLENGTH 8
set LASTLITERALS 5
set MFLIMIT [ expr $WILDCOPYLENGTH + $MINMATCH ]

set MAXD_LOG 16
set MAX_DISTANCE [ expr ((1 << $MAXD_LOG) - 1) ]

set ML_BITS 4
set ML_MASK [ expr (1 << $ML_BITS) - 1 ]
set RUN_BITS [ expr 8 - $ML_BITS ]
set RUN_MASK [ expr (1 << $RUN_BITS) - 1 ]

set LZ4_MAX_INPUT_SIZE 0x7e000000

proc LZ4_read8 { Pptr } {
	global HEAP
	set ofs [ expr $Pptr * 2 ]
	return 0x[ string range $HEAP $ofs [ expr $ofs + 1 ] ]
}

proc LZ4_read8o { Pptr ofs } {
	return [ LZ4_read8 [ expr $Pptr + $ofs ] ]
}

proc LZ4_read16 { Pptr } {
	# This procedure reads 16-bit data as big-endian
	global HEAP
	set ofs [ expr $Pptr * 2 ]
	return 0x[ string range $HEAP $ofs [ expr $ofs + 3 ] ]
}

proc LZ4_read32 { Pptr } {
	# This procedure reads 32-bit data as big-endian
	global HEAP
	set ofs [ expr $Pptr * 2 ]
	return 0x[ string range $HEAP $ofs [ expr $ofs + 7 ] ]
}

proc LZ4_write8 { Pptr val } {
	global HEAP
	set ofs [ expr $Pptr * 2 ]
	binary scan [ binary format c $val ] H2 hex
	set HEAP [ string replace $HEAP $ofs [ expr $ofs + 1 ] $hex ]
	return {}
}

proc LZ4_writeLE16 { Pptr val } {
	global HEAP
	set ofs [ expr $Pptr * 2 ]
	binary scan [ binary format s $val ] H4 hex
	set HEAP [ string replace $HEAP $ofs [ expr $ofs + 3 ] $hex ]
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

proc LZ4_compressBound { isize } {
	global LZ4_MAX_INPUT_SIZE
	if { $isize > $LZ4_MAX_INPUT_SIZE } {
		return 0
	} else {
		return [ expr $isize + ($isize / 255) + 16 ]
	}
}

#--------------------------------------------------------------------------------
# lz4hc.c
#
set OPTIMAL_ML [ expr ($ML_MASK - 1) + $MINMATCH ]

proc LZ4HC_hashPtr { Pptr } {
	global MINMATCH LZ4HC_HASH_LOG LZ4HC_HASH_MASK
	set i [ LZ4_read32 $Pptr ]
	return [ expr ((($i * 2654435761)) \
		>> (($MINMATCH * 8) - $LZ4HC_HASH_LOG)) & $LZ4HC_HASH_MASK ]
}

proc LZ4HC_init { RAhc4 Pstart } {
	global LZ4HC_HASHTABLESIZE LZ4HC_MAXD
	upvar $RAhc4 Ahc4

	array set Ahc4 [ list \
		LhashTable      [ lrepeat $LZ4HC_HASHTABLESIZE 0 ] \
		LchainTable     [ lrepeat $LZ4HC_MAXD 65535 ] \
		nextToUpdate    65536 \
		Pbase           [ expr $Pstart - 65536 ] \
		Pend            $Pstart \
		PdictBase       [ expr $Pstart - 65536 ] \
		dictLimit       65536 \
		lowLimit        65536 \
	]
	return {}
}

proc LZ4HC_Insert { RAhc4 Pip } {
	global MAX_DISTANCE
	upvar $RAhc4 Ahc4

	set Pbase $Ahc4(Pbase)
	set target [ expr $Pip - $Pbase ]
	set idx $Ahc4(nextToUpdate)

	while { $idx < $target } {
		set h [ LZ4HC_hashPtr [ expr $Pbase + $idx ] ]
		set delta [ expr $idx - [ lindex $Ahc4(LhashTable) $h ] ]
		if { $delta > $MAX_DISTANCE } { set delta $MAX_DISTANCE }
		lset Ahc4(LchainTable) [ expr $idx & 0xffff ] [ expr $delta & 0xffff ]
		lset Ahc4(LhashTable) $h [ expr $idx & 0xffffffff ]
		incr idx
	}

	set Ahc4(nextToUpdate) $target
	return {}
}

proc LZ4HC_InsertAndFindBestMatch { RAhc4 Pip PiLimit RPmatchpos maxNbAttempts } {
	global MINMATCH
	upvar $RAhc4 Ahc4 $RPmatchpos Pmatchpos

	set Pbase $Ahc4(Pbase)
	set PdictBase $Ahc4(PdictBase)
	set dictLimit $Ahc4(dictLimit)
	if { ($Ahc4(lowLimit) + 65536) > ($Pip - $Pbase) } {
		set lowLimit $Ahc4(lowLimit)
	} else {
		set lowLimit [ expr ($Pip - $Pbase) - (65536 - 1) ]
	}
	set matchIndex {}
	set nbAttempts $maxNbAttempts
	set ml 0

	# HC4 match finder
	LZ4HC_Insert Ahc4 $Pip
	set matchIndex [ lindex $Ahc4(LhashTable) [ LZ4HC_hashPtr $Pip ] ]

	while { ($matchIndex >= $lowLimit) && ($nbAttempts) } {
		incr nbAttempts -1
		if { $matchIndex >= $dictLimit } {
			set Pmatch [ expr $Pbase + $matchIndex ]
			if { ( [ LZ4_read8o $Pmatch $ml ] == [ LZ4_read8o $Pip $ml ] ) \
				&& ( [ LZ4_read32 $Pmatch ] == [ LZ4_read32 $Pip ] ) } {
				set mlt [ expr [ LZ4_count [ expr $Pip + $MINMATCH ] \
					[ expr $Pmatch + $MINMATCH ] $PiLimit ] + $MINMATCH ]
				if { $mlt > $ml } { set ml $mlt; set Pmatchpos $Pmatch }
			}
		} else {
			set Pmatch [ expr $PdictBase + $matchIndex ]
			if { [ LZ4_read32 $Pmatch ] == [ LZ4_read32 $Pip ] } {
				set mlt {}
				set PvLimit [ expr $Pip + ($dictLimit - $matchIndex) ]
				if { $PvLimit > $PiLimit } { set PvLimit $PiLimit }
				set mlt [ expr [ LZ4_count [ expr $Pip + $MINMATCH ] \
					[ expr $Pmatch + $MINMATCH ] $PvLimit ] + $MINMATCH ]
				if { $mlt > $ml } {
					set ml $mlt
					set Pmatchpos [ expr $Pbase + $matchIndex ]
				}
			}
		}
		incr matchIndex -[ lindex $Ahc4(LchainTable) [ expr $matchIndex & 0xffff ] ]
	}

	return $ml
}

proc LZ4HC_InsertAndGetWiderMatch { RAhc4 Pip PiLowLimit PiHighLimit longest \
	RPmatchpos RPstartpos maxNbAttempts } {
	global MINMATCH
	upvar $RAhc4 Ahc4 $RPmatchpos Pmatchpos $RPstartpos Pstartpos

	set Pbase $Ahc4(Pbase)
	set dictLimit $Ahc4(dictLimit)
	set PlowPrefixPtr [ expr $Pbase + $dictLimit ]
	if { ($Ahc4(lowLimit) + 65536) > ($Pip - $Pbase) } {
		set lowLimit $Ahc4(lowLimit)
	} else {
		set lowLimit [ expr $Pip - $Pbase ]
	}
	set PdictBase $Ahc4(PdictBase)
	set matchIndex {}
	set nbAttempts $maxNbAttempts
	set delta [ expr $Pip - $PiLowLimit ]

	# First Match
	LZ4HC_Insert Ahc4 $Pip
	set matchIndex [ lindex $Ahc4(LhashTable) [ LZ4HC_hashPtr $Pip ] ]

	while { ($matchIndex >= $lowLimit) && ($nbAttempts) } {
		incr nbAttempts -1
		if { $matchIndex >= $dictLimit } {
			set PmatchPtr [ expr $Pbase + $matchIndex ]
			if { [ LZ4_read8o $PiLowLimit $longest ] == \
				[ LZ4_read8 [ expr $PmatchPtr - $delta + $longest ] ] } {
				if { [ LZ4_read32 $PmatchPtr ] == [ LZ4_read32 $Pip ] } {
					set mlt [ expr $MINMATCH + [ LZ4_count \
						[ expr $Pip + $MINMATCH ] \
						[ expr $PmatchPtr + $MINMATCH ] $PiHighLimit ] ]
					set back 0

					while { (($Pip + $back) > $PiLowLimit) \
						&& (($PmatchPtr + $back) > $PlowPrefixPtr) \
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
			set PmatchPtr [ expr $PdictBase + $matchIndex ]
			if { [ LZ4_read32 $PmatchPtr ] == [ LZ4_read32 $Pip ] } {
				set mlt {}
				set back 0
				set PvLimit [ expr $Pip + $dictLimit - $matchIndex ]
				if { $PvLimit > $PiHighLimit } { set PvLimit $PiHighLimit }
				set mlt [ expr [ LZ4_count [ expr $Pip + $MINMATCH ] \
					[ expr $PmatchPtr + $MINMATCH ] $PvLimit ] + $MINMATCH ]
				if { (($Pip + $mlt) == $PvLimit) && ($PvLimit < $PiHighLimit) } {
					incr mlt [ LZ4_count [ expr $Pip + $mlt ] \
						[ expr $Pbase + $dictLimit ] $PiHighLimit ]
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
					set Pmatchpos [ expr $Pbase + $matchIndex + $back ]
					set Pstartpos [ expr $Pip + $back ]
				}
			}
		}
		incr matchIndex -[ lindex $Ahc4(LchainTable) [ expr $matchIndex & 0xffff ] ]
	}

	return $longest
}

set noLimit 0
set limitedOutput 1

proc LZ4HC_encodeSequence { RPip RPop RPanchor matchLength Pmatch limitedOutputBuffer Poend } {
	global LASTLITERALS RUN_MASK ML_BITS MINMATCH ML_MASK
	upvar $RPip Pip $RPop Pop $RPanchor Panchor
	set length {}
	set Ptoken {}
	set token {}

	if { 0 } {
		puts "literal : [ expr $Pip - $Panchor \
			]  --  match : $matchLength  --  offset : [ expr $Pip - $Pmatch ]"
	}

	# Encode Literal Length
	set length [ expr $Pip - $Panchor ]
	set Ptoken $Pop; incr Pop
	# Check output limit
	if { ($limitedOutputBuffer) \
		&& (($Pop + ($length >> 8) + $length + (2 + 1 + $LASTLITERALS)) > $Poend) } {
		return 1
	}
	if { $length >= $RUN_MASK } {
		set len {}
		# LZ4_write8 $Ptoken [ expr $RUN_MASK << $ML_BITS ]
		set token [ expr $RUN_MASK << $ML_BITS ]
		set len [ expr $length - $RUN_MASK ]
		for {} { $len > 254 } { incr len -255 } {
			LZ4_write8 $Pop 255; incr Pop
		}
		LZ4_write8 $Pop $len; incr Pop
	} else {
		# LZ4_write8 $Ptoken [ expr $length << $ML_BITS ]
		set token [ expr $length << $ML_BITS ]
	}

	# Copy Literals
	memcpy $Pop $Panchor $length
	incr Pop $length

	# Encode Offset
	LZ4_writeLE16 $Pop [ expr $Pip - $Pmatch ]; incr Pop 2

	# Encode MatchLength
	set length [ expr $matchLength - $MINMATCH ]
	# Check output limit
	if { ($limitedOutputBuffer) \
		&& (($Pop + ($length >> 8) + (1 + $LASTLITERALS)) > $Poend) } {
		return 1
	}
	if { $length >= $ML_MASK } {
		# LZ4_write8 $Ptoken [ expr [ LZ4_read8 $Ptoken ] + $ML_MASK ]
		LZ4_write8 $Ptoken [ expr $token + $ML_MASK ]
		incr length -$ML_MASK
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
		# LZ4_write8 $Ptoken [ expr [ LZ4_read8 $Ptoken ] + $length ]
		LZ4_write8 $Ptoken [ expr $token + $length ]
	}

	# Prepare next loop
	incr Pip $matchLength
	set Panchor $Pip

	return 0
}

proc LZ4HC_compress_generic { RActx Psource Pdest inputSize maxOutputSize \
	compressionLevel limit } {
	global MFLIMIT LASTLITERALS LZ4HC_MAX_CLEVEL LZ4HC_DEFAULT_CLEVEL \
		OPTIMAL_ML MINMATCH ML_MASK RUN_MASK ML_BITS
	upvar $RActx Actx

	set Pip $Psource
	set Panchor $Pip
	set Piend [ expr $Pip + $inputSize ]
	set Pmflimit [ expr $Piend - $MFLIMIT ]
	set Pmatchlimit [ expr $Piend - $LASTLITERALS ]

	set Pop $Pdest
	set Poend [ expr $Pop + $maxOutputSize ]

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
	incr Actx(Pend) $inputSize

	incr Pip

	# Main Loop
	while { $Pip < $Pmflimit } {
		set ml [ LZ4HC_InsertAndFindBestMatch Actx $Pip $Pmatchlimit Pref $maxNbAttempts ]
		if { !$ml } { incr Pip; continue }

		# saved, in case we would skip too much
		set Pstart0 $Pip
		set Pref0 $Pref
		set ml0 $ml

		set cont_s2 1
		# _Search2:
		while { $cont_s2 } {
			if { ($Pip + $ml) < $Pmflimit } {
				set ml2 [ LZ4HC_InsertAndGetWiderMatch Actx [ expr $Pip + $ml - 2 ] \
					[ expr $Pip + 0 ] $Pmatchlimit $ml Pref2 Pstart2 $maxNbAttempts ]
			} else {
				set ml2 $ml
			}
			if { $ml2 == $ml } {
				# No better match
				if { [ LZ4HC_encodeSequence Pip Pop Panchor $ml $Pref $limit $Poend ] } {
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
				if { ($Pstart2 - $Pip) < $OPTIMAL_ML } {
					set new_ml $ml
					if { $new_ml > $OPTIMAL_ML } { set new_ml $OPTIMAL_ML }
					if { ($Pip + $new_ml) > ($Pstart2 + $ml2 + $MINMATCH) } {
						set new_ml [ expr ($Pstart2 - $Pip) + $ml2 - $MINMATCH ]
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
					set ml3 [ LZ4HC_InsertAndGetWiderMatch Actx [ expr $Pstart2 + $ml2 - 3 ] \
						$Pstart2 $Pmatchlimit $ml2 Pref3 Pstart3 $maxNbAttempts ]
				} else {
					set ml3 $ml2
				}
				if { $ml3 == $ml2 } {
					# No better match : 2 sequences to encode
					# ip & ref are known; Now for ml
					if { $Pstart2 < ($Pip + $ml) } { set ml [ expr $Pstart2 - $Pip ] }
					# Now, encode 2 sequences
					if { [ LZ4HC_encodeSequence Pip Pop Panchor $ml $Pref $limit $Poend ] } {
						return 0
					}
					set Pip $Pstart2
					if { [ LZ4HC_encodeSequence Pip Pop Panchor $ml2 $Pref2 $limit $Poend ] } {
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
							if { $ml2 < $MINMATCH } {
								set Pstart2 $Pstart3
								set Pref2 $Pref3
								set ml2 $ml3
							}
						}

						if { [ LZ4HC_encodeSequence Pip Pop Panchor $ml $Pref $limit $Poend ] } {
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
					if { ($Pstart2 - $Pip) < $ML_MASK } {
						if { $ml > $OPTIMAL_ML } { set ml $OPTIMAL_ML }
						if { ($Pip + $ml) > ($Pstart2 + $ml2 - $MINMATCH) } {
							set ml [ expr ($Pstart2 - $Pip) + $ml2 - $MINMATCH ]
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
				if { [ LZ4HC_encodeSequence Pip Pop Panchor $ml $Pref $limit $Poend ] } {
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
	# Check output limit
	if { ($limit) && ($Pop + $lastRun + 1 \
		+ (($lastRun + 255 - $RUN_MASK) / 255) > $maxOutputSize) } {
		return 0
	}
	if { $lastRun >= $RUN_MASK } {
		LZ4_write8 $Pop [ expr $RUN_MASK << $ML_BITS ]; incr Pop
		incr lastRun -$RUN_MASK
		for {} { $lastRun > 254 } { incr lastRun -255 } {
			LZ4_write8 $Pop 255; incr Pop
		}
		LZ4_write8 $Pop $lastRun; incr Pop
	} else {
		LZ4_write8 $Pop [ expr $lastRun << $ML_BITS ]; incr Pop
	}
	memcpy $Pop $Panchor [ expr $Piend - $Panchor ]
	incr Pop [ expr $Piend - $Panchor ]

	# End
	return [ expr $Pop - $Pdest ]
}

proc LZ4_compress_HC_extStateHC { RAstate Psrc Pdst srcSize maxDstSize compressionLevel } {
	global limitedOutput noLimit
	upvar $RAstate Actx

	LZ4HC_init Actx $Psrc
	if { $maxDstSize < [ LZ4_compressBound $srcSize ] } {
		LZ4HC_compress_generic Actx $Psrc $Pdst $srcSize $maxDstSize $compressionLevel $limitedOutput
	} else {
		LZ4HC_compress_generic Actx $Psrc $Pdst $srcSize $maxDstSize $compressionLevel $noLimit
	}
}

proc LZ4_compress_HC { Psrc Pdst srcSize maxDstSize compressionLevel } {
	array set state [ list ]
	LZ4_compress_HC_extStateHC state $Psrc $Pdst $srcSize $maxDstSize $compressionLevel
}

proc LZ4_compress_HC_tcl { src maxDstSize compressionLevel } {
	global HEAP
	set Psrc 0
	set srcSize [ string length $src ]
	set Pdst [ expr $Psrc + ($srcSize + 7) & ~7 ]
	set maxHeap [ expr $Pdst + ($maxDstSize + 7) & ~7 ]

	# Allocate heap
	init_heap $maxHeap
	str2heap $Psrc $src

	# Execute compression
	set len [ LZ4_compress_HC $Psrc $Pdst $srcSize $maxDstSize $compressionLevel ]

	# Receive result
	set result [ heap2str $Pdst $len ]

	# Release heap
	unset HEAP

	return $result
}

