using FASTER.core;

namespace Accumulator.Wallet;

public class Wallet
{
    public long Balance;
    public long SeqNum;
}

public class WalletFunctions : FunctionsBase<long, Wallet, Wallet, Wallet, Empty>
{
    public override bool ConcurrentReader(ref long key, ref Wallet input, ref Wallet value, ref Wallet dst,
        ref ReadInfo readInfo)
    {
        dst = value;
        return true;
    }

    public override bool SingleReader(ref long key, ref Wallet input, ref Wallet value, ref Wallet dst,
        ref ReadInfo readInfo)
    {
        dst = value;
        return true;
    }

    public override bool ConcurrentWriter(ref long key, ref Wallet input, ref Wallet src, ref Wallet dst,
        ref Wallet output, ref UpsertInfo upsertInfo)
    {
        dst = src;
        output = dst;
        return true;
    }

    public override bool SingleWriter(ref long key, ref Wallet input, ref Wallet src, ref Wallet dst,
        ref Wallet output, ref UpsertInfo upsertInfo, WriteReason reason)
    {
        dst = src;
        output = dst;
        return true;
    }

    public override bool InitialUpdater(ref long key, ref Wallet input, ref Wallet value, ref Wallet output,
        ref RMWInfo rmwInfo)
    {
        value = output = input;
        return true;
    }

    public override void PostInitialUpdater(ref long key, ref Wallet input, ref Wallet value, ref Wallet output,
        ref RMWInfo rmwInfo)
    {
        // No post-update logic needed
    }

    public override bool NeedInitialUpdate(ref long key, ref Wallet input, ref Wallet output, ref RMWInfo rmwInfo)
    {
        return true;
    }

    public override bool NeedCopyUpdate(ref long key, ref Wallet input, ref Wallet oldValue, ref Wallet output,
        ref RMWInfo rmwInfo)
    {
        return true;
    }

    public override bool CopyUpdater(ref long key, ref Wallet input, ref Wallet oldValue, ref Wallet newValue,
        ref Wallet output, ref RMWInfo rmwInfo)
    {
        newValue = output = new Wallet
        {
            Balance = oldValue.Balance + input.Balance,
            SeqNum = Math.Max(oldValue.SeqNum, input.SeqNum)
        };
        return true;
    }

    public override bool InPlaceUpdater(ref long key, ref Wallet input, ref Wallet value, ref Wallet output,
        ref RMWInfo rmwInfo)
    {
        value.Balance += input.Balance;
        value.SeqNum = Math.Max(value.SeqNum, input.SeqNum);
        output = value;
        return true;
    }

    public override void ReadCompletionCallback(ref long key, ref Wallet input, ref Wallet output, Empty ctx,
        Status status, RecordMetadata recordMetadata)
    {
        // Handle read completion (e.g., logging or metrics)
    }

    public override void RMWCompletionCallback(ref long key, ref Wallet input, ref Wallet output, Empty ctx,
        Status status, RecordMetadata recordMetadata)
    {
        // Handle RMW completion (e.g., logging or metrics)
    }

    public override void CheckpointCompletionCallback(int sessionID, string sessionName, CommitPoint commitPoint)
    {
        // Handle checkpoint completion (e.g., logging or recovery preparation)
    }
}