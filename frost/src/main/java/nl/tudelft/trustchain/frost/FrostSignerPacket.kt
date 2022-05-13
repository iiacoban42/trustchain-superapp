package nl.tudelft.trustchain.frost

import android.util.Log
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
            serializeCoeff += serializeVarLen(coeff)
        }
        val count = pubcoeff.count()
        val length = byteArrayOf(count.toByte())
//        length += pubcoeff.count()

        return serializeVarLen(pubkey) +
            serializeVarLen(pubnonce) +
            serializeVarLen(partial_sig) +
            serializeVarLen(vss_hash) +
            serializeVarLen(length) +
            serializeCoeff
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

            val (numOfCoeffs, numOfCoeffsSize) = deserializeVarLen(buffer, localOffset)
            localOffset += numOfCoeffsSize

            var pubCoeffArray: Array<ByteArray> = emptyArray()

            for (i in 0 until numOfCoeffs[0].toInt()){
                val (pubCoeff, pubCoeffSize) = deserializeVarLen(buffer, localOffset)
                localOffset += pubCoeffSize
                pubCoeffArray = append(pubCoeffArray, pubCoeff)
            }
            for (arr in pubCoeffArray) {
                Log.i("FROST DESERIALIZER", "pubcoeffarray ${arr}")
                for(el in arr) {
                    Log.i("FROST DESERIALIZER", "element ${el}")
                }
            }

            return Pair(
                FrostSignerPacket(pubKey, pubNonce, partialSig, vssHash, pubCoeffArray),
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


