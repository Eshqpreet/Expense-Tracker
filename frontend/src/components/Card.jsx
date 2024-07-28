import { FaLocationDot, FaRupeeSign } from "react-icons/fa6";
import { BsCardText } from "react-icons/bs";
import { MdOutlinePayments } from "react-icons/md";
import { FaSackDollar } from "react-icons/fa6";
import { FaTrash } from "react-icons/fa";
import { HiPencilAlt } from "react-icons/hi";
import { Link, useMatch } from "react-router-dom";
import { formatDate } from "../utils/formateDate";
import { useMutation } from "@apollo/client";
import { DELETE_TRANSACTION } from "../graphql/mutations/transaction.mutation";
import toast from "react-hot-toast";

const categoryColorMap = {
    saving: "from-green-700 to-green-400",
    expense: "from-pink-800 to-pink-600",
    investment: "from-blue-700 to-blue-400",
    // Add more categories and corresponding color classes as needed
};

const Card = ({ transaction, authUser }) => {
    let { category, description, amount, location, date, paymentType } = transaction;
    description = description[0].toUpperCase() + description.slice(1);
    const cardType = category;
    category = category[0].toUpperCase() + category.slice(1);
    date = formatDate(date);
    paymentType = paymentType === 'upi' ? paymentType.toUpperCase() : paymentType[0].toUpperCase() + paymentType.slice(1);
    location = location ? location[0].toUpperCase() + location.slice(1) : "N/A";

    const cardClass = categoryColorMap[cardType];

    const [deleteTransaction, { loading }] = useMutation(DELETE_TRANSACTION, {
        refetchQueries: ['GetTransactions']
    });

    const handleDelete = async () => {
        try {
            await deleteTransaction({
                variables: {
                    transactionId: transaction._id
                }
            })
            toast.success("Transcation deleted successfully");
        } catch (err) {
            toast.error(err.message);
        }
    }

    return (
        <div className={`rounded-md p-4 bg-gradient-to-br ${cardClass}`}>
            <div className='flex flex-col gap-3'>
                <div className='flex flex-row items-center justify-between'>
                    <h2 className='text-lg font-bold text-white'>{category}</h2>
                    <div className='flex items-center gap-2'>
                        {!loading && <FaTrash className={"cursor-pointer"} onClick={handleDelete} />}
                        {loading && <div className="w-6 h-6 border-t-2 border-b-2 mx-1 rounded-full animate-spin"></div>}
                        <Link to={`/transaction/${transaction?._id}`}>
                            <HiPencilAlt className='cursor-pointer' size={20} />
                        </Link>
                    </div>
                </div>
                <p className='text-white flex items-center gap-1'>
                    <BsCardText />
                    Description: {description}
                </p>
                <p className='text-white flex items-center gap-1'>
                    <MdOutlinePayments />
                    Payment Type: {paymentType}
                </p>
                <p className='text-white flex items-center gap-1'>
                    <FaRupeeSign />
                    Amount: ₹{amount}
                </p>
                <p className='text-white flex items-center gap-1'>
                    <FaLocationDot />
                    Location: {location}
                </p>
                <div className='flex justify-between items-center'>
                    <p className='text-xs text-black font-bold'>{date}</p>
                    <img
                        src={authUser?.profilePicture}
                        className='h-8 w-8 border rounded-full'
                        alt=''
                    />
                </div>
            </div>
        </div>
    );
};
export default Card;