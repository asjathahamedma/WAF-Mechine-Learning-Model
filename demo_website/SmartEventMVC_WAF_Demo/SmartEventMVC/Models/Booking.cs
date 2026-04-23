using System;
using System.Collections.Generic;

namespace SmartEventMVC.Models;

public partial class Booking
{
    public int BookingId { get; set; }

    public int? MemberId { get; set; }

    public int? EventId { get; set; }

    public decimal? TotalAmount { get; set; }

    public string? PaymentType { get; set; }

    public DateTime? BookingDate { get; set; }

    public string? Status { get; set; }

    public virtual ICollection<BookingSeat> BookingSeats { get; set; } = new List<BookingSeat>();

    public virtual Event? Event { get; set; }

    public virtual Member? Member { get; set; }
}
