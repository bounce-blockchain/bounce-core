using Accumulator.Wallet;
using FASTER.core;
using Grpc.Core;

namespace Accumulator.gRPC;

public class WalletServiceImpl : WalletService.WalletServiceBase
{
    private readonly FasterKV<long, Wallet.Wallet> _store;

    public WalletServiceImpl(FasterKV<long, Wallet.Wallet> store)
    {
        _store = store;
    }

    public override Task<WalletBatchUpdateResponse> UpdateWallets(WalletBatchUpdateRequest request, ServerCallContext context)
    {
        using var session = _store.NewSession(new WalletFunctions());
        foreach (var update in request.Updates)
        {
            if (session.Read(update.WalletId, out var wallet).Found)
            {
                if (update.SeqNum > wallet.SeqNum)
                {
                    wallet.Balance += update.Amount;
                    wallet.SeqNum = update.SeqNum;
                    session.Upsert(update.WalletId, wallet);
                }
            }
        }

        return Task.FromResult(new WalletBatchUpdateResponse { Success = true });
    }
}

