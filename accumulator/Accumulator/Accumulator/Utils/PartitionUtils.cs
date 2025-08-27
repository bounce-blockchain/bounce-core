// This source code can be freely used for research purposes.
// For any other purpose, please contact the authors.

namespace Accumulator.Utils;

public class PartitionUtils
{
    public static int GetPartition(long walletId, int totalPartitions)
    {
        return (int)(walletId % totalPartitions);
    }

}