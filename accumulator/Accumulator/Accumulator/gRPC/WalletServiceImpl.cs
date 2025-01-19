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

    public override Task<WalletUpdateResponse> UpdateWallet(WalletUpdateRequest request, ServerCallContext context)
    {
        using var session = _store.NewSession(new WalletFunctions());
        if (session.Read(request.WalletId, out var wallet).Found)
        {
            wallet.Balance += request.Amount;
            wallet.SeqNum = request.SeqNum;
            session.Upsert(request.WalletId, wallet);
            return Task.FromResult(new WalletUpdateResponse { Success = true });
        }

        return Task.FromResult(new WalletUpdateResponse { Success = false });
    }
}
