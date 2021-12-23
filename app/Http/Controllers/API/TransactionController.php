<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\Transaction;
use App\Models\TransactionItem;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Redis;

class TransactionController extends Controller
{
    public function all(Request $request)
    {
         $id = $request->input('id');
         $limit = $request->input('limit', 6);
         $status = $request->input('status');

     //mengambil data berdasakan id
        if ($id) {
            $transaction = Transaction::with(['items.product'])->find($id);

            if($transaction)
            {
                return ResponseFormatter::success(
                    $transaction,
                    'Data transaksi berhasil diambil'
                );
            }
            else
            {
                return ResponseFormatter::error(
                    null,
                    'Data transaksi tidak ada',
                    404
                );
            }
        }

          $transaction = Transaction::with(['items.product'])->where('users_id', Auth::user()->id);

          if($status)
          {
              $transaction->where('status', $status);
          }

          return ResponseFormatter::success(
              $transaction->paginate($limit),
              'Data list transaksi berhasil diambil'
          );
    }

    public function checckout(Request $request)
    {
        $request->validate([
            'items' => 'required|array',
            'items.*.id' => 'exists:product,id',
            'total_price' => 'required',
            'shipping_price' => 'required',
            'status' => 'required|in:PENDING,SUCCESS,CANCELLED,FAILED,SHIPPING,SHIPPED',
        ]);

        $transaction = Transaction::create([
            'users_id' => Auth::user()->id,
            'address' => $request->address,
            'total_price' => $request->total_price,
            'shipping_price' => $request->shipping_price,
            'status' => $request->status,
        ]);

        foreach ($request->items as $product) {
            TransactionItem::create([
                'users_id' => Auth::user()->id,
                'products_id' => $product['id'],
                'transactions_id'=> $transaction->id,
                'quantity' => $product['quantity']
            ]);
        }

         return ResponseFormatter::success($transaction->load('item.product'), 'Transaksi berhasil');
    }

}