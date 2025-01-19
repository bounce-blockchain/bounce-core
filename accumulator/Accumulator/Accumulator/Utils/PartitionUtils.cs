namespace Accumulator.Utils;

public class PartitionUtils
{
    public static int GetPartition(long walletId, int totalPartitions)
    {
        return (int)(walletId % totalPartitions);
    }

}