package nl.tudelft.trustchain.frost

import androidx.core.graphics.component1
import androidx.core.graphics.component2
import nl.tudelft.ipv8.messaging.*

class FrostSignerPacket constructor(
    val pubkey: ByteArray,
    val pubnonce: ByteArray,
    val partial_sig: ByteArray,
    val vss_hash: ByteArray,
    val pubcoeff: Array<ByteArray>,
) : Serializable {
    override fun serialize(): ByteArray {
        var serializeCoeff = byteArrayOf()
        for (coeff in pubcoeff) {
            serializeCoeff += coeff
        }
        return serializeVarLen(pubkey) +
            serializeVarLen(pubnonce) +
            serializeVarLen(partial_sig) +
            serializeVarLen(vss_hash) +
            serializeUShort(pubcoeff.size) +
            serializeVarLen(serializeCoeff)
    }

    companion object Deserializer : Deserializable<FrostSignerPacket> {
        override fun deserialize(buffer: ByteArray, offset: Int): Pair<FrostSignerPacket, Int> {
            var localOffset = offset
            val (pubKey, pubKeySize) = deserializeVarLen(buffer, localOffset)
            localOffset += pubKeySize
            val (pubNonce, pubNonceSize) = deserializeVarLen(buffer, localOffset)
            localOffset += pubNonceSize
            val (partialSig, partialSigSize) = deserializeVarLen(buffer, localOffset)
            localOffset += partialSigSize
            val (vssHash, vssHashSize) = deserializeVarLen(buffer, localOffset)
            localOffset += vssHashSize

            val (numOfCoeffs, numOfCoeffsSize) = deserializeUShort(buffer, localOffset)
            localOffset += numOfCoeffsSize

            val (pubcoeffAll, pubcoeffSize) = deserializeVarLen(buffer, localOffset)
            localOffset += pubcoeffSize

            val pubCoeff: MutableList<ByteArray> = mutableListOf()

            var i = 0

            while (i < pubcoeffAll.size-numOfCoeffs+1){
                val subArr = pubcoeffAll.copyOfRange(i, i+numOfCoeffs)
                pubCoeff.add(subArr)
                i += numOfCoeffs
            }

//            var pubCoeffArray: Array<ByteArray> = emptyArray()
//
//            for (i in 0 until numOfCoeffs){
//                val (pubCoeff, pubCoeffSize) = deserializeVarLen(buffer, localOffset)
//                localOffset += pubCoeffSize
//                pubCoeffArray = append(pubCoeffArray, pubCoeff)
//            }

//            val pubcoeff = pubcoeffAll.chunked

            return Pair(
                FrostSignerPacket(pubKey, pubNonce, partialSig, vssHash, pubCoeff.toTypedArray()),
                localOffset - offset
            )
        }
        private fun append(arr: Array<ByteArray>, element: ByteArray): Array<ByteArray> {
            val list: MutableList<ByteArray> = arr.toMutableList()
            list.add(element)
            return list.toTypedArray()
        }
    }
}


