using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SmartEventMVC.Models
{
    public class Inquiry
    {
        [Key]
        public int InquiryId { get; set; }

        [Required]
        [StringLength(100)]
        public string? Name { get; set; }

        [Required]
        [StringLength(15)]
        public string? Mobile { get; set; }

        [Required]
        [StringLength(500)]
        public string? Message { get; set; }

        public int? EventId { get; set; }

        [ForeignKey("EventId")]
        public virtual Event? Event { get; set; }

        public DateTime? InquiryDate { get; set; } = DateTime.Now;

        [StringLength(20)]
        public string? Status { get; set; } = "Pending";

        [StringLength(500)]
        public string? AdminReply { get; set; }

        public DateTime? ReplyDate { get; set; }

        [StringLength(100)]
        public string? RepliedBy { get; set; }
    }
}